"""ARMv5TE instruction tests for arm-v5t.

arm-v5t runs on cores that implement ARMv5TE, so these raw assembly programs
check the instructions ARMv5TE added to ARMv5T:

- ``v5te_qarith``: saturating arithmetic (qadd, qdadd, qdsub) and the Q flag
- ``v5te_mul``: signed halfword multiplies (smulxy, smlaxy, smulwy, smlawy,
  smlalxy)
- ``v5te_ldrd``: doubleword loads and stores (ldrd, strd) and the pld hint
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Callable, Sequence

from .common import (
    TRITON_ARCHS,
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
    "armv5t": PlatformSpec("ARM_V5T", "LITTLE"),
    "armv5tbe": PlatformSpec("ARM_V5T", "BIG"),
}

_MASK = 0xFFFFFFFF


@dataclasses.dataclass(frozen=True)
class _Spec:
    platform: PlatformSpec
    engines: tuple[str, ...] = _ENGINES


def _s32(value: int) -> int:
    value &= _MASK
    return value - (1 << 32) if value >> 31 else value


def _s16(value: int) -> int:
    value &= 0xFFFF
    return value - (1 << 16) if value >> 15 else value


def _sat(value: int) -> tuple[int, bool]:
    clamped = max(-(1 << 31), min((1 << 31) - 1, value))
    return clamped, clamped != value


def _qarith_expected(arg: int) -> int:
    a, qa = _sat(_s32(arg) + 0x7FFFFFF0)
    doubled, qd1 = _sat(2 * _s32(arg))
    b, qb = _sat(_s32(arg) + doubled)
    c, qc = _sat(0 - doubled)
    q = qa or qd1 or qb or qc
    return ((a ^ b ^ c) & _MASK) ^ (int(q) << 4)


def _mul_expected(arg: int) -> int:
    r0 = arg & _MASK
    r1 = ((r0 >> 16) | (r0 << 16)) & _MASK
    bb = _s16(r0) * _s16(r1)
    bt = _s16(r0) * _s16(r1 >> 16)
    tt = _s16(r0 >> 16) * _s16(r1 >> 16)
    wb = (_s32(r0) * _s16(r1)) >> 16
    wt = ((_s32(r0) * _s16(r1 >> 16)) >> 16) + r0
    r2 = ((bb + bt) ^ tt ^ wb ^ wt) & _MASK
    acc = (r2 + bb) & 0xFFFFFFFFFFFFFFFF
    return ((acc & _MASK) + (acc >> 32)) & _MASK


def _ldrd_expected(arg: int) -> int:
    first = arg & _MASK
    second = ~arg & _MASK
    return (first - (second ^ 0x5A5A5A5A) + second) & _MASK


_ARCHS = tuple(_PLATFORMS)

# Measured backend gaps, used as skip reasons below.
_ANGR_NO_QADD = "angr's Iop_QAdd32S, which VEX lifts qadd to, fails on a scalar operand"
_PCODE_NO_SATURATE = (
    "Ghidra's SLEIGH saturates the already-wrapped 32-bit result through "
    "SignedSaturate userops the emulator doesn't implement"
)
_TRITON_NO_DSP = "Triton implements no ARMv5TE DSP instruction semantics"

# family -> (expected-result function, arguments, skip reasons)
_FAMILIES: dict[str, tuple[Callable[[int], int], tuple[int, ...], dict]] = {
    # 5 saturates nothing; 0x40000000 saturates qadd, qdadd and qdsub.
    "v5te_qarith": (
        _qarith_expected,
        (5, 0x40000000),
        {
            **{f"{arch}.angr": _ANGR_NO_QADD for arch in _ARCHS},
            **{f"{arch}.pcode": _PCODE_NO_SATURATE for arch in _ARCHS},
            "armv5t.triton": _TRITON_NO_DSP,
        },
    ),
    # 0x8001FFFE has a negative top half and a -2 bottom half.
    "v5te_mul": (
        _mul_expected,
        (0x12345678, 0x8001FFFE),
        {"armv5t.triton": _TRITON_NO_DSP},
    ),
    "v5te_ldrd": (_ldrd_expected, (5, 0x12345678), {}),
}

_SPECS = {
    family: {
        arch: _Spec(
            _PLATFORMS[arch],
            # Triton has no big-endian ARM.
            (
                _ENGINES
                if arch in TRITON_ARCHS
                else tuple(e for e in _ENGINES if e != "triton")
            ),
        )
        for arch in _ARCHS
    }
    for family in _FAMILIES
}

SCENARIO_PREFIXES = tuple((family, family) for family in _FAMILIES)


def _expectations(family: str):
    expected, args, _ = _FAMILIES[family]
    return tuple(((str(arg),), f"{expected(arg):#x}") for arg in args)


SCENARIO_INFOS = tuple(
    ScenarioInfo(
        prefix=family,
        scenario=family,
        tags=("scenario", "armv5te_isa", family),
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

    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(code.address + code.get_capacity())

    final_machine = machine.emulate(emulator)
    print(hex(final_machine.get_cpu().r0.get()))
    return 0
