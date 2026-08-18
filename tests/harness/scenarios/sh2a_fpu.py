"""SH-2A-FPU floating-point coverage.

The FPU is the whole reason SH-2A-FPU is a distinct platform from plain SH-2A,
and until these scenarios existed the suite exercised exactly one floating-point
instruction (``floats``, a single-precision ``fadd``).  That left the four
backends' floating-point paths - three independent sleigh/pcode models and a
locally patched QEMU - effectively untested against each other.

Three scenarios, each a small focused blob so a failure localises to a few
instructions:

``sh2a_fpu``
    Single-precision arithmetic, sign manipulation, ``fldi0``/``fldi1``,
    ``fmac``, and integer/bit conversion through FPUL.

``sh2a_fpu_double``
    The same arithmetic under ``FPSCR.PR = 1``.  The instructions assemble to the
    *same encodings* as their single-precision spellings - SuperH picks precision
    at runtime - so this is also a differential probe: identical bytes must
    produce different results under the two FPSCR settings.

``sh2a_fpu_overlay``
    The ``DRn = FRn:FRn+1`` register overlay, checked from inside the guest via
    ``flds``/``sts`` rather than through the harness's register model, plus
    SH-2A's 32-bit displaced floating-point moves and a single/double round trip
    that switches ``FPSCR.PR`` mid-blob.

Every expectation is an exact IEEE-754 bit pattern.  Operands are chosen so each
result is exactly representable, so no rounding mode can change them and there is
no tolerance to tune.  Results are compared by the runner below rather than by
matching stdout, so a mismatch reports every differing register at once.
"""

from __future__ import annotations

import dataclasses
import logging
import struct
import types
from typing import Dict, Mapping, Sequence, Tuple

from .common import (
    PlatformSpec,
    load_raw_code,
    make_emulator,
    make_platform,
    set_register,
    split_variant,
)
from .spec import ScenarioInfo, from_arch_table, just_run

NATIVE_PARITY = True

_ARCH = "sh2a"
_PLATFORM = PlatformSpec("SUPERH_SH2A_FPU", "BIG")

# FPSCR words.  Bit 19 is PR (precision), bit 20 is SZ (fmov transfer size), bit
# 18 is DN (denormals are zero) and bits 0-1 are the rounding mode; 1 is
# round-to-zero, which is also what the hardware comes up in.  SZ stays 0
# throughout: it controls `fmov` width independently of PR, and conflating the
# two in one test would make a failure ambiguous.
FPSCR_SINGLE = 0x00040001
FPSCR_DOUBLE = 0x000C0001

# SH FPSCR carries two accumulating status fields alongside its control bits:
# Cause at bits 17-12 and Flag at bits 6-2, each holding E/V/Z/O/U/I. Panda runs
# a real CPU model and accumulates them - `ftrc fr4,fpul` on 3.75 is an inexact
# conversion, so Panda ends this blob at 0x00040005 rather than 0x00040001 -
# while Ghidra's and Styx's sleigh models implement no floating-point exceptions
# at all and leave them clear. Neither is wrong, so the exact word is not a
# cross-backend invariant; mask both fields out and keep checking the parts that
# are (PR, RM, DN, SZ).
FPSCR_STATUS_FIELDS = 0x0003F07C
FPSCR_CONTROL_MASK = ~FPSCR_STATUS_FIELDS

# Ghidra's SH-2A sleigh models the FPU as single-precision only, and every
# pcode-derived backend inherits that.  `superh.sinc` defines
# `@define FP_PR "fpscr[19,1]"` and then never references it again - one grep hit
# in the whole file, the definition itself - while every arithmetic rule is
# unconditionally single:
#
#     :fadd  ffrm_04_07, ffrn_08_11 ... { ffrn_08_11 = ffrn_08_11 f+ ffrm_04_07; }
#     :fsqrt ffrn_08_11             ... { ffrn_08_11 = sqrt(ffrn_08_11); }
#
# operating on the 4-byte `fr` registers.  Ghidra's *SH-4* spec by contrast
# references FPSCR.PR 31 times, so the omission is specific to the SH-2A model.
#
# The observable effect is that a double-precision instruction performs
# single-precision arithmetic on the *upper 32 bits* of each dr and leaves the
# low half zero.  Minimal reproducer: with FPSCR.PR=1 and dr6 = 4.0
# (0x4010000000000000), `fsqrt dr6` should give 2.0 (0x4000000000000000); Ghidra
# gives 0x3fc0000000000000, which is float32 sqrt(2.25) - 2.25 being dr6's upper
# half read as a binary32 - sitting in the upper half.
#
# This also explains the failure previously attributed to Styx alone: "1.5 + 2.25
# -> 480.0" is exactly this bug.  The single-precision sum of the two upper
# halves (1.9375 + 2.03125 = 3.96875, 0x407e0000) placed in a double's high half
# is 0x407e000000000000 = 480.0.  Styx bundles the same Ghidra sleigh, so it
# inherits the defect rather than causing it.
_SLEIGH_NO_DOUBLE = (
    "Ghidra's SH-2A sleigh ignores FPSCR.PR and is single-precision only "
    "(fsqrt of 4.0 gives 0.125); affects every pcode-derived backend"
)

# angr's pcode engine implements *no* floating-point operations, for any
# architecture.  All eighteen OpBehaviorFloat* classes in
# angr/engines/pcode/behavior.py inherit the base
# `evaluate_binary`/`evaluate_unary`, which raise `AngrError("Not implemented!")`;
# each carries the Ghidra C++ implementation as a comment above a file-level note
# reading "reference code from Ghidra which will need to be ported".  By contrast
# OpBehaviorIntAdd and friends are implemented.  So this is an upstream angr
# limitation affecting every pcode-backed architecture - SuperH, TriCore, MSP430,
# Xtensa, LoongArch - and not something these tests can work around.
_ANGR_NO_FP = "angr's pcode engine implements no floating-point arithmetic: every OpBehaviorFloat* in angr/engines/pcode/behavior.py is unimplemented (upstream, affects every pcode-backed arch)"

# NOTE: PANDA's SH-2A support comes from nix/patches/panda-qemu-sh2a.patch, which
# needs a libpanda built with the sh4eb target.  That target is built (see
# nix/panda-packages.nix), so the panda variants below are live and unskipped -
# there is deliberately no panda entry in `_SKIPS`.


def f32(value: float) -> int:
    """The binary32 bit pattern of ``value``, as SuperH stores it in an fr."""
    return struct.unpack(">I", struct.pack(">f", value))[0]


def f64(value: float) -> int:
    """The binary64 bit pattern of ``value``, as SuperH stores it in a dr."""
    return struct.unpack(">Q", struct.pack(">d", value))[0]


@dataclasses.dataclass(frozen=True)
class FpuCaseSpec:
    """One floating-point blob: what to put in, and what must come out."""

    platform: PlatformSpec
    engines: Tuple[str, ...]
    fpscr: int
    inputs: Mapping[str, int]
    expected: Mapping[str, int]
    stack_base: int = 0x2000
    stack_size: int = 0x4000
    # Bits to ignore when comparing a register, by name. Needed where backends
    # legitimately disagree: a real CPU model accumulates FPSCR's exception
    # flags, while sleigh models no floating-point exceptions at all, so an
    # exact FPSCR is not a cross-backend invariant. `sh2a_diff` drops FPSCR from
    # its comparison entirely for the same reason; masking keeps the parts that
    # *are* invariant - precision, rounding mode, denormal handling - checked.
    masks: Mapping[str, int] = types.MappingProxyType({})


# --------------------------------------------------------------------------
# sh2a_fpu - single precision
# --------------------------------------------------------------------------
_SINGLE_INPUTS = {
    "fr0": f32(1.5),
    "fr1": f32(2.25),
    "fr2": f32(0.5),
    "fr3": f32(4.0),
}

_SINGLE_EXPECTED = {
    # Inputs must survive: every operation copies before operating, so a backend
    # that clobbers a neighbouring fr shows up here rather than silently.
    "fr0": f32(1.5),
    "fr1": f32(2.25),
    "fr2": f32(0.5),
    "fr3": f32(4.0),
    # Arithmetic.
    "fr4": f32(3.75),  # fadd  1.5 + 2.25
    "fr5": f32(-0.75),  # fsub  1.5 - 2.25
    "fr6": f32(3.375),  # fmul  1.5 * 2.25
    "fr7": f32(8.0),  # fdiv  4.0 / 0.5
    "fr8": f32(2.0),  # fsqrt sqrt(4.0)
    # Sign manipulation.
    "fr9": f32(-1.5),  # fneg
    "fr10": f32(0.75),  # fabs  |-0.75|
    # Immediate loads.
    "fr11": f32(0.0),  # fldi0
    "fr12": f32(1.0),  # fldi1
    # Multiply-accumulate: FR0*FR1 + FR13.
    "fr13": f32(3.875),  # 1.5 * 2.25 + 0.5
    # flds/fsts move raw bits, so this is fr1 copied bit-for-bit, not converted.
    "fr14": f32(2.25),
    "fr15": f32(7.0),  # float, from the integer 7
    # ftrc truncates toward zero: 3.75 -> 3.
    "r1": 3,
    "r2": 7,
    # The last thing to touch FPUL is `flds fr1, fpul`.
    "fpul": f32(2.25),
    "fpscr": FPSCR_SINGLE,
}

# --------------------------------------------------------------------------
# sh2a_fpu_double - double precision
# --------------------------------------------------------------------------
_DOUBLE_INPUTS = {
    "dr0": f64(1.5),
    "dr2": f64(2.25),
    "dr4": f64(0.5),
    "dr6": f64(4.0),
    "dr8": f64(1.5),
    "dr10": f64(1.5),
    "dr12": f64(-0.75),
    "dr14": f64(4.0),
}

_DOUBLE_EXPECTED = {
    "dr0": f64(-1.5),  # fneg
    "dr2": f64(2.25),  # operand, unchanged
    "dr4": f64(9.0),  # float, from the integer 9
    "dr6": f64(2.0),  # fsqrt sqrt(4.0)
    "dr8": f64(8.4375),  # fadd then fmul: (1.5 + 2.25) * 2.25
    "dr10": f64(-0.75),  # fsub  1.5 - 2.25
    "dr12": f64(0.75),  # fabs  |-0.75|
    "dr14": f64(8.0),  # fdiv  4.0 / 0.5
    "r1": 8,  # ftrc  trunc(8.0)
    "r3": 1,  # fcmp/eq dr2, dr2
    "r4": 1,  # fcmp/gt: 2.25 >  -1.5
    "r5": 0,  # fcmp/gt: -1.5 >  2.25
    "fpscr": FPSCR_DOUBLE,
}

# --------------------------------------------------------------------------
# sh2a_fpu_overlay - the dr/fr overlay and SH-2A's 32-bit FP memory forms
# --------------------------------------------------------------------------
# Deliberately asymmetric halves, so swapping them is unmistakable.
_OVERLAY_DR0 = 0x3FF0000000000001
_OVERLAY_PATTERN = 0x0BADF00D

_OVERLAY_INPUTS = {
    "dr0": _OVERLAY_DR0,
    "dr2": f64(0.75),
    "fr6": _OVERLAY_PATTERN,
    # Written as two singles; the runner checks they compose into dr10.  The blob
    # never touches these.
    "fr10": 0x11112222,
    "fr11": 0x33334444,
}

_OVERLAY_EXPECTED = {
    # The overlay as the *guest* sees it: fr0 is the high half of dr0.
    "r1": _OVERLAY_DR0 >> 32,
    "r2": _OVERLAY_DR0 & 0xFFFFFFFF,
    # SH-2A 32-bit displaced store/load round trip, then the indirect,
    # post-increment and pre-decrement forms.
    "fr7": _OVERLAY_PATTERN,
    "fr8": _OVERLAY_PATTERN,
    "fr9": _OVERLAY_PATTERN,
    # fcnvds narrowed 0.75 to binary32; fcnvsd widened it back.
    "r4": f32(0.75),
    "dr4": f64(0.75),
    # The harness-visible half of the overlay: two singles read back as one
    # double, high half first.
    "dr10": 0x1111222233334444,
    # FPSCR words built by movi20s + add.
    "r3": FPSCR_DOUBLE,
    "r5": FPSCR_SINGLE,
    "fpscr": FPSCR_SINGLE,
}


def _spec(engines: Tuple[str, ...], fpscr: int, inputs, expected) -> FpuCaseSpec:
    return FpuCaseSpec(
        platform=_PLATFORM,
        engines=engines,
        fpscr=fpscr,
        inputs=inputs,
        expected=expected,
        masks=types.MappingProxyType({"fpscr": FPSCR_CONTROL_MASK}),
    )


# angr variants are declared and skipped rather than omitted, so the manifest
# records *why* a backend is absent instead of silently narrowing coverage.
# Panda is a live engine here: the QEMU SH-2A instruction port is built (see
# nix/patches/panda-qemu-sh2a.patch), and it is the only backend that computes
# double precision correctly at all.  Styx is omitted from the double-precision
# scenarios outright, because there the whole blob is unusable rather than one
# instruction class.
_SINGLE_ENGINES = ("angr", "pcode", "styx", "panda")
_DOUBLE_ENGINES = ("angr", "pcode", "panda")

SPECS: Dict[str, Dict[str, FpuCaseSpec]] = {
    "sh2a_fpu": {
        _ARCH: _spec(_SINGLE_ENGINES, FPSCR_SINGLE, _SINGLE_INPUTS, _SINGLE_EXPECTED)
    },
    "sh2a_fpu_double": {
        _ARCH: _spec(_DOUBLE_ENGINES, FPSCR_DOUBLE, _DOUBLE_INPUTS, _DOUBLE_EXPECTED)
    },
    # Styx runs the overlay fine, measured: the fcnvds/fcnvsd conversions are
    # precision-aware in the sleigh even though the *arithmetic* is not, so this
    # blob's PR=1 section is unaffected by the single-precision defect.
    "sh2a_fpu_overlay": {
        _ARCH: _spec(_SINGLE_ENGINES, FPSCR_SINGLE, _OVERLAY_INPUTS, _OVERLAY_EXPECTED)
    },
}

_SKIPS: Dict[str, Dict[str, str]] = {
    "sh2a_fpu": {
        f"{_ARCH}.angr": _ANGR_NO_FP,
    },
    # This scenario is the executable specification of the sleigh defect above:
    # its expectations are the architecturally correct double-precision results.
    # angr and pcode are skipped because they cannot produce them; PANDA is NOT
    # skipped and is the single load-bearing engine here - it runs real QEMU,
    # whose translate.c does branch on FPSCR.PR.  So the whole double-precision
    # signal rests on `sh2a_fpu_double:sh2a.panda`; do not narrow it further
    # without replacing the coverage.
    "sh2a_fpu_double": {
        f"{_ARCH}.angr": _ANGR_NO_FP,
        f"{_ARCH}.pcode": _SLEIGH_NO_DOUBLE,
    },
    "sh2a_fpu_overlay": {
        f"{_ARCH}.angr": _ANGR_NO_FP,
    },
}

SCENARIO_PREFIXES = tuple((name, name) for name in sorted(SPECS))


def _run(scenario: str, variant: str, spec: FpuCaseSpec) -> int:
    """Seed the registers named by ``spec``, run ``scenario``, compare the result.

    Generic over the blob: the caller supplies the spec, so other SH-2A scenarios
    can reuse this instead of reimplementing the setup.
    """
    import smallworld

    arch, engine = split_variant(variant)

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, scenario, arch)
    machine.add(code)

    stack = smallworld.state.memory.stack.Stack.for_platform(
        platform, spec.stack_base, spec.stack_size
    )
    machine.add(stack)
    set_register(cpu, "sp", stack.get_pointer())
    set_register(cpu, "pc", code.address)

    # FPSCR before the operands: on SuperH it decides how every subsequent
    # floating-point instruction behaves, and a backend that latches precision
    # at operand-write time rather than at use time would be wrong.
    set_register(cpu, "fpscr", spec.fpscr)
    for name, value in spec.inputs.items():
        set_register(cpu, name, value)

    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(code.address + code.get_capacity())

    final = machine.emulate(emulator)
    return _report(final.get_cpu(), spec)


def _report(cpu, spec: FpuCaseSpec) -> int:
    failures: list[str] = []
    for name in sorted(spec.expected):
        want = spec.expected[name]
        raw = getattr(cpu, name).get()
        width = getattr(cpu, name).size * 2
        mask = spec.masks.get(name, ~0)
        if isinstance(raw, int):
            got = f"{raw:#0{width + 2}x}"
            ok = (raw & mask) == (want & mask)
            if ok and raw != want:
                got += f" (masked {mask & ((1 << (width * 4)) - 1):#x})"
        else:
            # angr can hand back a claripy bitvector if a value stayed symbolic.
            # That is a failure, not something to coerce: it means the blob read
            # state the harness never concretised.
            got = f"symbolic:{raw}"
            ok = False
        line = f"  {name:6} = {got:<20} want {want:#0{width + 2}x}"
        if ok:
            print(line)
        else:
            print(f"{line}   MISMATCH")
            failures.append(name)

    if failures:
        print(f"FAIL: {len(failures)} register(s) differ: {', '.join(failures)}")
        return 1
    print(f"OK: {len(spec.expected)} registers match")
    return 0


def _info(scenario: str) -> ScenarioInfo:
    return ScenarioInfo(
        prefix=scenario,
        scenario=scenario,
        tags=("scenario", scenario, "sh2a", "fpu"),
        variants_source=from_arch_table(
            SPECS[scenario], skip_reasons=_SKIPS.get(scenario)
        ),
        run_factory=just_run(),
    )


SCENARIO_INFOS = tuple(_info(name) for name in sorted(SPECS))


# Public aliases.  `sh2a_delayslot` reuses this "seed registers, run, compare
# registers" runner rather than duplicating it, the same way several scenarios
# reuse `raw_binary.run_integer_case`.  The spec type is not FPU-specific - it
# just happens to have been written here first.
RegisterCaseSpec = FpuCaseSpec
run_register_case = _run
report_registers = _report


def can_run(scenario: str, variant: str) -> bool:
    specs = SPECS.get(scenario)
    if specs is None:
        return False
    arch, engine = split_variant(variant)
    return arch in specs and engine in specs[arch].engines


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    arch, _ = split_variant(variant)
    return _run(scenario, variant, SPECS[scenario][arch])
