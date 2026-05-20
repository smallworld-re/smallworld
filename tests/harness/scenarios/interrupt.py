from __future__ import annotations

import logging
from typing import Sequence

from .common import (
    PlatformSpec,
    load_raw_code,
    make_emulator,
    make_platform,
    set_register,
    split_variant,
)
from .raw_binary import RawBinarySpec

_SPECS = {
    "aarch64": RawBinarySpec(
        platform=PlatformSpec("AARCH64", "LITTLE"),
        pc_register="pc",
        result_register="x0",
        arg_register="x0",
        engines=("unicorn", "panda"),
    ),
    "amd64": RawBinarySpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pc_register="rip",
        result_register="rax",
        arg_register="rdi",
        engines=("unicorn", "panda"),
    ),
    "armel": RawBinarySpec(
        platform=PlatformSpec("ARM_V5T", "LITTLE"),
        pc_register="pc",
        result_register="r0",
        arg_register="r0",
        engines=("unicorn", "panda"),
    ),
    "armhf": RawBinarySpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pc_register="pc",
        result_register="r0",
        arg_register="r0",
        engines=("unicorn", "panda"),
    ),
    "i386": RawBinarySpec(
        platform=PlatformSpec("X86_32", "LITTLE"),
        pc_register="eip",
        result_register="eax",
        arg_register="edi",
        engines=("unicorn", "panda"),
    ),
    "m68k": RawBinarySpec(
        platform=PlatformSpec("M68K", "BIG"),
        pc_register="pc",
        result_register="d0",
        arg_register="d0",
        engines=("unicorn",),
    ),
    "mips": RawBinarySpec(
        platform=PlatformSpec("MIPS32", "BIG"),
        pc_register="pc",
        result_register="v0",
        arg_register="a0",
        engines=("unicorn", "panda"),
    ),
    "mipsel": RawBinarySpec(
        platform=PlatformSpec("MIPS32", "LITTLE"),
        pc_register="pc",
        result_register="v0",
        arg_register="a0",
        engines=("unicorn", "panda"),
    ),
    "ppc": RawBinarySpec(
        platform=PlatformSpec("POWERPC32", "BIG"),
        pc_register="pc",
        result_register="r3",
        arg_register="r3",
        engines=("unicorn", "panda"),
    ),
}


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
