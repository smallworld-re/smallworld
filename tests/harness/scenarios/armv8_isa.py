"""ARMv8-only instruction tests for the 32-bit ARMv8 platforms.

Each family is a raw assembly program built only from instructions ARMv8
added, so an ARMv7 core rejects it (or, for the stack limits, ignores it):

- ``v8_acqrel``: acquire/release loads and stores (lda, stl, ldaex, stlex)
- ``v8_crc32``: the CRC32 instructions (crc32b, crc32w)
- ``v8_fp``: the ARMv8 floating-point additions (vrinta, vmaxnm, vsel, vcvta)
- ``v8m_stacklimit``: ARMv8-M's stack-limit registers (msplim, psplim)
"""

from __future__ import annotations

import dataclasses
import logging
import zlib
from typing import Sequence

from .common import (
    PlatformSpec,
    load_raw_code,
    make_emulator,
    make_platform,
    set_register,
    split_variant,
)
from .spec import ScenarioInfo, assert_outputs, from_arch_table

NATIVE_PARITY = True

_ENGINES = ("unicorn", "angr", "pcode", "triton", "panda", "styx")

_PLATFORMS = {
    "armv8a": PlatformSpec("ARM_V8A", "LITTLE"),
    "armv8r": PlatformSpec("ARM_V8R", "LITTLE"),
    "armv8m": PlatformSpec("ARM_V8M", "LITTLE"),
}


@dataclasses.dataclass(frozen=True)
class _Spec:
    platform: PlatformSpec
    engines: tuple[str, ...] = _ENGINES


def _crc_arm(acc: int, data: bytes) -> int:
    # ARM's CRC32 instructions apply no pre- or post-inversion.
    return ~zlib.crc32(data, ~acc & 0xFFFFFFFF) & 0xFFFFFFFF


def _crc32_expected(arg: int) -> int:
    acc = _crc_arm(0xFFFFFFFF, bytes([arg & 0xFF]))
    return _crc_arm(acc, arg.to_bytes(4, "little"))


# Measured backend gaps, used as skip reasons below.
_TRITON_NO_ACQREL = "Triton doesn't support the ARMv8 acquire/release instructions"
_TRITON_NO_DECODE = "Triton can't decode this ARMv8 instruction"
_TRITON_NO_FLOAT = "Triton implements no floating-point instruction semantics"
_ANGR_NO_CRC32 = "VEX can't decode the ARMv8 CRC32 instructions"
_ANGR_NO_MAXNUM = "angr doesn't implement VEX's Iop_MaxNumF32 (vmaxnm)"
_ANGR_NO_STACKLIMIT = (
    "angr doesn't model the ARMv8-M stack-limit registers; mrs reads a symbolic value"
)
_PCODE_NO_CRC32 = (
    "Ghidra's SLEIGH lifts crc32 to a Crc32Calc userop the emulator doesn't implement"
)
_PCODE_NO_V8FP = (
    "Ghidra's SLEIGH lifts these ARMv8 FP instructions to a coprocessor_function2 "
    "userop the emulator doesn't implement"
)
_PCODE_NO_STACKLIMIT = (
    "Ghidra's SLEIGH lifts msr msplim to a setMainStackPointerLimit userop "
    "the emulator doesn't implement"
)

# family -> (archs, [(argument, expected r0)], skip reasons)
_FAMILIES: dict[str, tuple[tuple[str, ...], tuple[tuple[int, int], ...], dict]] = {
    "v8_acqrel": (
        ("armv8a", "armv8r", "armv8m"),
        ((5, 2 * 5 + 1), (100, 2 * 100 + 1)),
        {
            f"{arch}.triton": _TRITON_NO_ACQREL
            for arch in ("armv8a", "armv8r", "armv8m")
        },
    ),
    "v8_crc32": (
        ("armv8a", "armv8r"),
        tuple((arg, _crc32_expected(arg)) for arg in (5, 0x12345678)),
        {
            **{f"{arch}.angr": _ANGR_NO_CRC32 for arch in ("armv8a", "armv8r")},
            **{f"{arch}.pcode": _PCODE_NO_CRC32 for arch in ("armv8a", "armv8r")},
            **{f"{arch}.triton": _TRITON_NO_DECODE for arch in ("armv8a", "armv8r")},
        },
    ),
    "v8_fp": (
        ("armv8a", "armv8r"),
        ((5, 6), (2, 3)),
        {
            **{
                f"{arch}.panda": "PANDA's ARM CPU starts with the VFP unit "
                "inaccessible, and enabling it needs a privileged CPACR write "
                "the harness cannot make"
                for arch in ("armv8a", "armv8r")
            },
            **{f"{arch}.angr": _ANGR_NO_MAXNUM for arch in ("armv8a", "armv8r")},
            **{f"{arch}.pcode": _PCODE_NO_V8FP for arch in ("armv8a", "armv8r")},
            **{f"{arch}.triton": _TRITON_NO_FLOAT for arch in ("armv8a", "armv8r")},
        },
    ),
    "v8m_stacklimit": (
        ("armv8m",),
        ((0x100, 2 * 0x100), (0x1FF, 2 * 0x1F8)),
        {
            "armv8m.angr": _ANGR_NO_STACKLIMIT,
            "armv8m.pcode": _PCODE_NO_STACKLIMIT,
            "armv8m.triton": _TRITON_NO_DECODE,
        },
    ),
}

_SPECS = {
    family: {arch: _Spec(_PLATFORMS[arch]) for arch in archs}
    for family, (archs, _, _) in _FAMILIES.items()
}

SCENARIO_PREFIXES = tuple((family, family) for family in _FAMILIES)


def _expectations(family: str):
    cases = _FAMILIES[family][1]
    return tuple(((str(arg),), f"{expected:#x}") for arg, expected in cases)


SCENARIO_INFOS = tuple(
    ScenarioInfo(
        prefix=family,
        scenario=family,
        tags=("scenario", "armv8_isa", family),
        variants_source=from_arch_table(_SPECS[family], skip_reasons=skips),
        run_factory=assert_outputs(_expectations(family)),
    )
    for family, (_, _, skips) in _FAMILIES.items()
)


def can_run(scenario: str, variant: str) -> bool:
    if scenario not in _SPECS:
        return False
    arch, engine = split_variant(variant)
    return arch in _SPECS[scenario] and engine in _SPECS[scenario][arch].engines


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    import smallworld

    if len(args) != 1:
        raise SystemExit(f"{scenario} expects one integer argument")
    argument = int(args[0], 0)
    arch, engine = split_variant(variant)
    spec = _SPECS[scenario][arch]

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, scenario, arch)
    machine.add(code)
    set_register(cpu, "pc", code.address)
    set_register(cpu, "r0", argument)

    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
    machine.add(stack)
    stack.push_integer(0xFFFFFFFF, 4, "fake return address")
    set_register(cpu, "sp", stack.get_pointer())

    if engine == "unicorn" and hasattr(cpu, "fpexc") and hasattr(cpu, "cpacr"):
        # Unicorn resets ARM CPUs with the FPU disabled; enable it as an OS
        # would for a user process.
        cpu.cpacr.set(0x00F00000)  # Full access to coprocessors 10 and 11
        cpu.fpexc.set(0x40000000)  # FPEXC.EN

    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(code.address + code.get_capacity())

    final_machine = machine.emulate(emulator)
    print(hex(final_machine.get_cpu().r0.get()))
    return 0
