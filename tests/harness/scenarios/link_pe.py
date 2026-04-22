from __future__ import annotations

import dataclasses
import logging
from typing import Sequence

from .common import (
    PlatformSpec,
    add_code_bounds,
    load_pe_code,
    load_pe_library,
    make_emulator,
    make_noop_model,
    make_platform,
    maybe_enable_linear,
    push_cli_argv,
    set_register,
    split_variant,
)


@dataclasses.dataclass(frozen=True)
class LinkPESpec:
    platform: PlatformSpec
    pointer_size: int
    pc_register: str
    stack_pointer_register: str
    result_register: str
    engines: tuple[str, ...]
    init_offset: int
    exit_offset: int
    argument_registers: tuple[str, str] | None = None


_SPECS = {
    "amd64": LinkPESpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pointer_size=8,
        pc_register="rip",
        stack_pointer_register="rsp",
        result_register="rax",
        engines=("unicorn", "angr", "panda", "pcode"),
        init_offset=0x16C0,
        exit_offset=0x10D2,
        argument_registers=("rcx", "rdx"),
    ),
    "i386": LinkPESpec(
        platform=PlatformSpec("X86_32", "LITTLE"),
        pointer_size=4,
        pc_register="eip",
        stack_pointer_register="esp",
        result_register="eax",
        engines=("unicorn", "angr", "panda", "pcode"),
        init_offset=0x15E0,
        exit_offset=0x10BF,
    ),
}


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "link_pe":
        return False
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    if len(args) != 1:
        raise SystemExit(f"{scenario} expects one string argument")

    import smallworld

    arch, engine = split_variant(variant)
    spec = _SPECS[arch]

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_pe_code(smallworld, "link_pe", arch, platform, address=0x400000)
    machine.add(code)
    lib = load_pe_library(smallworld, "link_pe", arch, platform, address=0x800000)
    machine.add(lib)

    code.link_pe(lib)

    entrypoint = code.address + 0x1000
    set_register(cpu, spec.pc_register, entrypoint)

    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
    machine.add(stack)
    _, argv = push_cli_argv(stack, args[0], pointer_size=spec.pointer_size)
    if arch == "i386":
        stack.push_integer(0xC001D00D, 4, None)
    set_register(cpu, spec.stack_pointer_register, stack.get_pointer())

    if spec.argument_registers is not None:
        argc_register, argv_register = spec.argument_registers
        set_register(cpu, argc_register, 2)
        set_register(cpu, argv_register, argv)

    machine.add(
        make_noop_model(
            smallworld,
            name="_main",
            platform=platform,
            address=code.address + spec.init_offset,
        )
    )

    emulator = make_emulator(smallworld, platform, engine)
    maybe_enable_linear(smallworld, emulator, engine)
    emulator.add_exit_point(0)
    emulator.add_exit_point(code.address + spec.exit_offset)
    add_code_bounds(machine, code, lib)

    final_cpu = machine.emulate(emulator).get_cpu()
    print(hex(getattr(final_cpu, spec.result_register).get()))
    return 0
