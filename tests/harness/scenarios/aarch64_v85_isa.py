"""ARMv8.1-ARMv8.5 instruction tests for aarch64-v8.5a.

Each family is a raw assembly program built from instructions ARMv8.1 to
ARMv8.5 added, which a plain ARMv8.0 aarch64 core rejects:

- ``v85_lse``: the ARMv8.1 LSE atomics (ldadd, swp, cas)
- ``v85_pauth``: ARMv8.3 pointer authentication (pacia, autia, xpaci) and the
  branch-protection hints (bti, paciasp, autiasp)
- ``v85_rcpc``: ARMv8.3 RCpc and ARMv8.4 LRCPC2 (ldapr, ldapur)
- ``v85_rdm``: the ARMv8.1 rounding doubling multiply-accumulate and
  -subtract (sqrdmlah, sqrdmlsh)
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

_ENGINES = ("unicorn", "angr", "pcode", "triton", "panda")

_PLATFORMS = {
    "aarch64v85a": PlatformSpec("AARCH64_V8_5A", "LITTLE"),
    "aarch64v85abe": PlatformSpec("AARCH64_V8_5A", "BIG"),
}

_MASK = 0xFFFFFFFFFFFFFFFF


@dataclasses.dataclass(frozen=True)
class _Spec:
    platform: PlatformSpec
    engines: tuple[str, ...] = _ENGINES


def _s32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value >> 31 else value


def _sqrdml(acc: int, n: int, m: int, subtract: bool) -> int:
    product = 2 * n * m
    if subtract:
        product = -product
    total = ((acc << 32) + product + (1 << 31)) >> 32
    return max(-(1 << 31), min((1 << 31) - 1, total))


def _rdm_expected(arg: int) -> int:
    acc = _sqrdml(5, _s32(arg), 0x40000000, False)
    return _sqrdml(acc, _s32(arg), -(1 << 31), True) & 0xFFFFFFFF


# Measured backend gaps, used as skip reasons below.
_ANGR_NO_DECODE = "VEX can't decode the ARMv8.1+ instructions"
_TRITON_NO_DECODE = "Triton implements no semantics for these ARMv8.1+ instructions"

# family -> (expected-result function, arguments, skip reasons)
_FAMILIES: dict[str, tuple[Callable[[int], int], tuple[int, ...], dict]] = {
    "v85_lse": (
        lambda arg: (2 * arg + 110) & _MASK,
        (5, 0x123456789),
        {
            "aarch64v85a.angr": _ANGR_NO_DECODE,
            "aarch64v85abe.angr": _ANGR_NO_DECODE,
            "aarch64v85a.triton": _TRITON_NO_DECODE,
        },
    ),
    "v85_pauth": (
        lambda arg: (2 * arg) & _MASK,
        (0x400000, 0x7FFFF0001000),
        {
            "aarch64v85a.angr": _ANGR_NO_DECODE,
            "aarch64v85abe.angr": _ANGR_NO_DECODE,
            "aarch64v85a.triton": _TRITON_NO_DECODE,
        },
    ),
    "v85_rcpc": (
        lambda arg: (2 * arg) & _MASK,
        (5, 0x123456789),
        {
            "aarch64v85a.angr": _ANGR_NO_DECODE,
            "aarch64v85abe.angr": _ANGR_NO_DECODE,
        },
    ),
    "v85_rdm": (
        _rdm_expected,
        (100, 0x7FFFFFFF),
        {
            "aarch64v85a.angr": _ANGR_NO_DECODE,
            "aarch64v85abe.angr": _ANGR_NO_DECODE,
            "aarch64v85a.triton": _TRITON_NO_DECODE,
        },
    ),
}

# Triton has no big-endian AArch64.
_SPECS = {
    family: {
        arch: _Spec(
            spec,
            (
                _ENGINES
                if arch in TRITON_ARCHS
                else tuple(e for e in _ENGINES if e != "triton")
            ),
        )
        for arch, spec in _PLATFORMS.items()
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
        tags=("scenario", "aarch64_v85_isa", family),
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
    set_register(cpu, "x0", argument)

    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
    machine.add(stack)
    set_register(cpu, "sp", stack.get_pointer())

    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(code.address + code.get_capacity())

    final_machine = machine.emulate(emulator)
    print(hex(final_machine.get_cpu().x0.get()))
    return 0
