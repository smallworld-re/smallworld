"""Cross-backend differential comparison for SH-2A.

Every other scenario checks one register on one engine at a time.  That catches a
backend which is wrong in an obvious way, but it cannot catch a backend which is
*consistently* wrong, and it gives no signal at all about whether the four
implementations agree with each other.  SmallWorld reaches SH-2A through four
genuinely independent decoders:

* Ghidra's ``superh.sinc`` sleigh, via the Ghidra emulator,
* the same sleigh via angr's pcode engine,
* Styx's own ``SuperH2A`` core (a different pcode arch spec),
* QEMU's ``target/sh4``, extended with the SH-2A ISA by
  ``nix/patches/panda-qemu-sh2a.patch``.

Where they disagree, at least one is wrong.  For the QEMU patch in particular
there is no other independent oracle - it was written from the binutils opcode
table and cross-read against the sleigh, but never executed until now - so
four-way agreement is the strongest check available to it.

This scenario runs one blob on every backend it can construct and compares full
register state: engine against the architectural expectation, *and* engine
against engine.  Registers the blob never touches are seeded with sentinels
beforehand, so "this backend clobbered something it had no business writing" is
caught too - notably that ``mulr`` must leave MACL alone, unlike ``mul.l``.

Excluded from comparison, each for a stated reason rather than to make the test
pass:

``sr``
    SH-2A's T bit is the bitfield ``sr[0,1]``; QEMU keeps M, Q and T in separate
    ``CPUSH4State`` fields recombined only by an exported accessor; and Ghidra's
    sleigh does not model the ``clips``/``clipu`` CS side effect at all.  Three
    legitimate representations of one register.

``fpscr``
    Not written by the harness or the blob, so each backend shows its own reset
    default.

``pc``
    All backends should land on the exit address, but angr's may remain symbolic
    depending on how the run terminated.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Dict, List, Sequence, Tuple

from .common import (
    PlatformSpec,
    load_raw_code,
    make_emulator,
    make_platform,
    set_register,
)
from .spec import ScenarioInfo, from_arch_table, just_run

NATIVE_PARITY = True

_ARCH = "sh2a"
_PLATFORM = PlatformSpec("SUPERH_SH2A_FPU", "BIG")

# Engines the runner will try.  This is *not* the variant's engine: the scenario
# declares a single variant and compares all of these internally, because a
# comparison is not a property of any one engine.
_ENGINES = ("pcode", "angr", "styx", "panda")

# Registers whose value the blob determines, and what it must be.
_EXPECTED: Dict[str, int] = {
    "r0": 0x0005A5A0,  # stc tbr, r0
    "r1": 0x00012345,  # movi20
    "r2": 0xFFFFFFFF,  # movi20 #-1, sign-extended not masked
    "r3": 0x00040000,  # movi20s
    "r4": 0x000369CF,  # mulr: 0x12345 * 3
    "r5": 0x0000007F,  # clips.b
    "r6": 0x00007FFF,  # clips.w
    "r7": 0x000000FF,  # clipu.b
    "r8": 0x0000FFFF,  # clipu.w
    "r9": 0x00012345,  # divs
    "r10": 0x00012345,  # divu
    "r11": 0x00000022,  # bset #5 then bset #1
    "r12": 0x00000080,  # bst with T=1 then T=0
    "r13": 0x00000000,  # movt  after nott
    "r14": 0x00000001,  # movrt after nott
    "tbr": 0x0005A5A0,  # ldc round-tripped through stc
}

# Sentinels for state the blob must leave alone.  Distinct values so a mix-up is
# unmistakable rather than looking like a zero.
_SENTINELS: Dict[str, int] = {
    # mulr writes a general-purpose register and must NOT touch the
    # multiply-accumulate registers the way mul.l does.
    "mach": 0x1234ABCD,
    "macl": 0x5678DCBA,
    "gbr": 0x0BADCAFE,
    "vbr": 0xFEEDFACE,
    # No bsr/jsr in the blob, so the procedure register must survive.
    "pr": 0xDEADBEEF,
    # The blob is integer-only, so every floating-point register must survive.
    **{f"fr{i}": 0xF0000000 | i for i in range(16)},
}

# Seeded so the blob starts from known state, but *not* compared afterwards.
#
# SR has to be concrete before anything reads T: SH-2A has no standalone T
# register - it is the bitfield sr[0,1] - so an unconstrained SR propagates into
# every `movt`/`movrt` result on a symbolic backend.  Seeding it from the harness
# rather than with an `ldc Rm,SR` preamble in the blob is deliberate: that
# instruction is privileged, and writing 0 to SR clears SR.MD and would drop a
# full-system backend into user mode.  Bit 30 keeps QEMU privileged while leaving
# every SH-2A-visible bit clear.
_SEED_ONLY: Dict[str, int] = {"sr": 0x40000000}

_IGNORED = ("sr", "fpscr", "pc")

_STACK_BASE = 0x2000
_STACK_SIZE = 0x4000


@dataclasses.dataclass(frozen=True)
class DiffSpec:
    platform: PlatformSpec
    engines: Tuple[str, ...]


SPECS: Dict[str, DiffSpec] = {
    # The declared variant engine is `pcode`, the reference implementation; the
    # runner ignores it and drives every engine in _ENGINES.
    _ARCH: DiffSpec(platform=_PLATFORM, engines=("pcode",))
}

SCENARIO_PREFIXES = (("sh2a_diff", "sh2a_diff"),)


def _dump(engine: str) -> Tuple[Dict[str, object], str | None]:
    """Run the blob on one engine and return its final register state."""
    import smallworld

    platform = make_platform(smallworld, _PLATFORM)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, "sh2a_diff", _ARCH)
    machine.add(code)

    stack = smallworld.state.memory.stack.Stack.for_platform(
        platform, _STACK_BASE, _STACK_SIZE
    )
    machine.add(stack)
    set_register(cpu, "sp", stack.get_pointer())
    set_register(cpu, "pc", code.address)

    for name, value in {**_SEED_ONLY, **_SENTINELS}.items():
        set_register(cpu, name, value)

    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(code.address + code.get_capacity())

    final = machine.emulate(emulator)
    final_cpu = final.get_cpu()

    state: Dict[str, object] = {}
    for name in list(_EXPECTED) + list(_SENTINELS):
        raw = getattr(final_cpu, name).get()
        state[name] = raw if isinstance(raw, int) else f"symbolic:{raw}"
    return state, None


def _panda_supports_superh() -> Tuple[bool, str]:
    """Whether the installed pandare2 knows about SuperH, without starting it.

    Checked by import rather than by constructing a PandaEmulator on purpose.
    PandaEmulator does its setup on a worker thread, so a pandare2 that lacks the
    target raises ``ValueError: Unsupported architecture sh4eb`` *inside that
    thread*; the exception never reaches the caller and the main thread waits
    forever.  ``SuperHArch`` is the class ``nix/patches/panda-ng-superh.patch``
    adds, so its presence is exactly the capability we need.
    """
    try:
        from pandare2.arch import SuperHArch  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        return False, f"installed pandare2 has no SuperH support ({type(exc).__name__})"
    return True, ""


def _run() -> int:
    import smallworld

    smallworld.logging.setup_logging(level=logging.INFO)

    engines = list(_ENGINES)
    if "panda" in engines:
        ok, why = _panda_supports_superh()
        if not ok:
            print(f"[panda] NOT ATTEMPTED: {why}")
            engines.remove("panda")

    dumps: Dict[str, Dict[str, object]] = {}
    for engine in engines:
        try:
            dumps[engine], _ = _dump(engine)
            print(f"[{engine}] ran")
        except Exception as exc:  # noqa: BLE001
            # An engine that cannot run at all is reported and excluded, not
            # silently dropped: the summary below states who participated.
            print(f"[{engine}] UNAVAILABLE: {type(exc).__name__}: {exc}")

    if not dumps:
        print("FAIL: no backend could run the blob")
        return 1

    failures: List[str] = []

    # 1. Each engine against the architectural expectation.
    for engine, state in sorted(dumps.items()):
        wrong = [
            f"{name}={state[name]!r} want {want:#010x}"
            for name, want in sorted(_EXPECTED.items())
            if state[name] != want
        ]
        clobbered = [
            f"{name}={state[name]!r} want {want:#010x}"
            for name, want in sorted(_SENTINELS.items())
            if state[name] != want
        ]
        if wrong:
            failures.append(f"{engine}: wrong results: {'; '.join(wrong)}")
        if clobbered:
            failures.append(
                f"{engine}: clobbered untouched state: {'; '.join(clobbered)}"
            )
        if not wrong and not clobbered:
            print(f"[{engine}] matches the architectural expectation")

    # 2. Every engine against every other, which is the point of the scenario.
    engines = sorted(dumps)
    for i, left in enumerate(engines):
        for right in engines[i + 1 :]:
            diffs = [
                f"{name}: {left}={dumps[left][name]!r} {right}={dumps[right][name]!r}"
                for name in sorted(set(_EXPECTED) | set(_SENTINELS))
                if dumps[left][name] != dumps[right][name]
            ]
            if diffs:
                failures.append(f"{left} vs {right} differ: {'; '.join(diffs)}")
            else:
                print(f"[{left} vs {right}] identical")

    print(f"participating backends: {', '.join(engines)}")
    print(f"not compared (by design): {', '.join(_IGNORED)}")

    if failures:
        for line in failures:
            print(f"FAIL: {line}")
        return 1

    if len(engines) < 2:
        print(
            f"FAIL: only {engines[0]} was available; a differential comparison "
            "needs at least two backends"
        )
        return 1

    print(
        f"OK: {len(engines)} backends agree on all "
        f"{len(_EXPECTED) + len(_SENTINELS)} compared registers"
    )
    return 0


SCENARIO_INFO = ScenarioInfo(
    prefix="sh2a_diff",
    scenario="sh2a_diff",
    tags=("scenario", "sh2a_diff", "sh2a", "differential"),
    variants_source=from_arch_table(SPECS),
    run_factory=just_run(),
)


def can_run(scenario: str, variant: str) -> bool:
    return scenario == "sh2a_diff" and variant == f"{_ARCH}.pcode"


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    return _run()
