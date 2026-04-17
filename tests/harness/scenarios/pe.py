from __future__ import annotations

import dataclasses
import logging
from typing import Sequence

from .common import (
    PlatformSpec,
    StringSource,
    load_pe_code,
    make_emulator,
    make_noop_model,
    make_platform,
    make_puts_model,
    maybe_enable_linear,
    set_register,
    split_variant,
)


@dataclasses.dataclass(frozen=True)
class PESpec:
    platform: PlatformSpec
    pointer_size: int
    pc_register: str
    stack_pointer_register: str
    engines: tuple[str, ...]
    puts_source: StringSource
    init_name: str
    init_offset: int
    exit_offset: int
    code_address: int | None = None


_SPECS = {
    "amd64": PESpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pointer_size=8,
        pc_register="rip",
        stack_pointer_register="rsp",
        engines=("unicorn", "angr", "panda", "pcode"),
        puts_source=StringSource(register="rcx"),
        init_name="__main",
        init_offset=0x1620,
        exit_offset=0x1031,
        code_address=0x10000,
    ),
    "i386": PESpec(
        platform=PlatformSpec("X86_32", "LITTLE"),
        pointer_size=4,
        pc_register="eip",
        stack_pointer_register="esp",
        engines=("unicorn", "angr", "panda", "pcode"),
        puts_source=StringSource(
            stack_pointer_register="esp",
            stack_offset=4,
            pointer_size=4,
            byteorder="little",
        ),
        init_name="___main",
        init_offset=0x1550,
        exit_offset=0x102E,
    ),
}


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "pe":
        return False
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    if args:
        raise SystemExit(f"{scenario} does not take extra arguments: {' '.join(args)}")

    import smallworld

    arch, engine = split_variant(variant)
    spec = _SPECS[arch]

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_pe_code(
        smallworld,
        "pe",
        arch,
        platform,
        address=spec.code_address,
    )
    machine.add(code)

    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
    machine.add(stack)
    stack.push_integer(0x10101010, spec.pointer_size, None)
    set_register(cpu, spec.stack_pointer_register, stack.get_pointer())

    machine.add(
        make_noop_model(
            smallworld,
            name=spec.init_name,
            platform=platform,
            address=code.address + spec.init_offset,
        )
    )

    puts = make_puts_model(
        smallworld,
        platform=platform,
        address=0x10000000,
        source=spec.puts_source,
    )
    code.update_import("api-ms-win-crt-stdio-l1-1-0.dll", "puts", puts._address)
    machine.add(puts)

    set_register(cpu, spec.pc_register, code.address + 0x1000)

    emulator = make_emulator(smallworld, platform, engine)
    maybe_enable_linear(smallworld, emulator, engine)
    emulator.add_exit_point(code.address + spec.exit_offset)
    machine.emulate(emulator)
    return 0
