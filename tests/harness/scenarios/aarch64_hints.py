"""AArch64 hint-space instruction tests.

``aarch64_hints`` runs every instruction in the hint space other than nop,
wfe and wfi: the pointer authentication and branch target identification
hints compilers emit for ``-mbranch-protection``, and the rest. On ARMv8.0 they
are all no-ops; on aarch64-v8.5a the pointer authentication ones sign and
authenticate in pairs, which gives the result back.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Sequence

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
    "aarch64": PlatformSpec("AARCH64", "LITTLE"),
    "aarch64be": PlatformSpec("AARCH64", "BIG"),
    "aarch64v85abe": PlatformSpec("AARCH64_V8_5A", "BIG"),
    "aarch64v85a": PlatformSpec("AARCH64_V8_5A", "LITTLE"),
}


@dataclasses.dataclass(frozen=True)
class _Spec:
    platform: PlatformSpec
    engines: tuple[str, ...] = _ENGINES


# Triton has no big-endian AArch64.
_SPECS = {
    arch: _Spec(
        platform,
        (
            _ENGINES
            if arch in TRITON_ARCHS
            else tuple(e for e in _ENGINES if e != "triton")
        ),
    )
    for arch, platform in _PLATFORMS.items()
}

_SCENARIO = "aarch64_hints"

_MASK = 0xFFFFFFFFFFFFFFFF

SCENARIO_PREFIXES = ((_SCENARIO, _SCENARIO),)

SCENARIO_INFOS = (
    ScenarioInfo(
        prefix=_SCENARIO,
        scenario=_SCENARIO,
        tags=("scenario", _SCENARIO),
        variants_source=from_arch_table(_SPECS),
        run_factory=assert_outputs(
            tuple(
                ((str(arg),), f"{(2 * arg) & _MASK:#x}") for arg in (5, 0x7FFFF0001000)
            )
        ),
    ),
)


def can_run(scenario: str, variant: str) -> bool:
    if scenario != _SCENARIO:
        return False
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    import smallworld

    if len(args) != 1:
        raise SystemExit(f"{scenario} expects one integer argument")
    argument = int(args[0], 0)
    arch, engine = split_variant(variant)

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, _PLATFORMS[arch])
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, scenario, arch)
    machine.add(code)
    set_register(cpu, "pc", code.address)
    set_register(cpu, "x0", argument)
    set_register(cpu, "lr", code.address + code.get_capacity())

    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
    machine.add(stack)
    set_register(cpu, "sp", stack.get_pointer())

    emulator = make_emulator(smallworld, platform, engine)
    emulator.add_exit_point(code.address + code.get_capacity())

    final_machine = machine.emulate(emulator)
    print(hex(final_machine.get_cpu().x0.get()))
    return 0
