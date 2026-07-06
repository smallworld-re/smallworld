from __future__ import annotations

import logging
from typing import Sequence

from .common import (
    build_specs,
    load_raw_code,
    make_emulator,
    make_platform,
    set_register,
    split_variant,
)
from .raw_binary import RawBinarySpec
from .spec import ScenarioInfo, from_arch_table, just_run

NATIVE_PARITY = True

_ARCHS = (
    "aarch64",
    "amd64",
    "armel",
    "armhf",
    "i386",
    "m68k",
    "mips",
    "mipsel",
    "ppc",
)

_ENGINES_UNICORN_PANDA = ("unicorn", "panda")

_SPECS = build_specs(
    RawBinarySpec,
    _ARCHS,
    engines={
        "aarch64": _ENGINES_UNICORN_PANDA,
        "amd64": _ENGINES_UNICORN_PANDA,
        "armel": _ENGINES_UNICORN_PANDA,
        "armhf": _ENGINES_UNICORN_PANDA,
        "i386": _ENGINES_UNICORN_PANDA,
        "m68k": ("unicorn",),
        "mips": _ENGINES_UNICORN_PANDA,
        "mipsel": _ENGINES_UNICORN_PANDA,
        "ppc": _ENGINES_UNICORN_PANDA,
    },
    # interrupt reads the full-width return register on amd64.
    per_arch={"amd64": {"result_register": "rax"}},
)


SCENARIO_PREFIXES = (("interrupt", "interrupt"),)

SCENARIO_INFO = ScenarioInfo(
    prefix="interrupt",
    scenario="interrupt",
    tags=("scenario", "interrupt"),
    variants_source=from_arch_table(
        _SPECS,
        skip_reasons={
            "amd64": "Interrupt hook doesn't fire",
            "i386": "Interrupt hook doesn't fire",
        },
    ),
    run_factory=just_run(),
)


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "interrupt":
        return False
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    import smallworld

    arch, engine = split_variant(variant)

    spec = _SPECS[arch]

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, "interrupt", arch)
    machine.add(code)
    set_register(cpu, spec.pc_register, code.address)
    emulator = make_emulator(smallworld, platform, engine)

    exit_point = code.address + code.get_capacity()
    machine.add_exit_point(exit_point)

    def interrupt_hook(emu: smallworld.emulators.Emulator, intno: int) -> bool:
        print(f"Received interrupt {intno}")
        raise smallworld.exceptions.EmulationStop()

    emulator.hook_interrupts(interrupt_hook)

    machine.emulate(emulator)

    return 0
