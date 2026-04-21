from __future__ import annotations

import dataclasses
import logging
from typing import Sequence

from .common import (
    PlatformSpec,
    StringSource,
    load_elf_code,
    make_emulator,
    make_platform,
    make_puts_model,
    maybe_enable_linear,
    resolve_ppc64_function_descriptor,
    set_register,
    split_variant,
)


@dataclasses.dataclass(frozen=True)
class RelaSpec:
    platform: PlatformSpec
    pointer_size: int
    pc_register: str
    stack_pointer_register: str
    engines: tuple[str, ...]
    string_source: StringSource
    load_address: int | None = None
    function_descriptor_entrypoint: bool = False
    print_entrypoint: bool = False


_SPECS = {
    "aarch64": RelaSpec(
        platform=PlatformSpec("AARCH64", "LITTLE"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("unicorn", "angr", "panda", "pcode"),
        string_source=StringSource(register="x0"),
        load_address=0x400000,
    ),
    "amd64": RelaSpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pointer_size=8,
        pc_register="rip",
        stack_pointer_register="rsp",
        engines=("unicorn", "angr", "panda", "pcode"),
        string_source=StringSource(register="rdi"),
        load_address=0x400000,
    ),
    "armel": RelaSpec(
        platform=PlatformSpec("ARM_V6M", "LITTLE"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("unicorn", "angr", "panda", "pcode"),
        string_source=StringSource(register="r0"),
        print_entrypoint=True,
    ),
    "armhf": RelaSpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("unicorn", "angr", "panda", "pcode"),
        string_source=StringSource(register="r0"),
        load_address=0x400000,
        print_entrypoint=True,
    ),
    "i386": RelaSpec(
        platform=PlatformSpec("X86_32", "LITTLE"),
        pointer_size=4,
        pc_register="eip",
        stack_pointer_register="esp",
        engines=("unicorn", "angr", "panda", "pcode"),
        string_source=StringSource(
            stack_pointer_register="esp",
            stack_offset=4,
            pointer_size=4,
            byteorder="little",
        ),
        load_address=0x400000,
        print_entrypoint=True,
    ),
    "la64": RelaSpec(
        platform=PlatformSpec("LOONGARCH64", "LITTLE"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("angr", "pcode"),
        string_source=StringSource(register="a0"),
        print_entrypoint=True,
    ),
    "m68k": RelaSpec(
        platform=PlatformSpec("M68K", "BIG"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("unicorn", "pcode"),
        string_source=StringSource(
            stack_pointer_register="sp",
            stack_offset=4,
            pointer_size=4,
            byteorder="big",
        ),
        load_address=0x40000,
        print_entrypoint=True,
    ),
    "mips": RelaSpec(
        platform=PlatformSpec("MIPS32", "BIG"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("unicorn", "angr", "panda", "pcode"),
        string_source=StringSource(register="a0"),
        print_entrypoint=True,
    ),
    "mips64": RelaSpec(
        platform=PlatformSpec("MIPS64", "BIG"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("unicorn", "angr", "panda", "pcode"),
        string_source=StringSource(register="a0"),
        print_entrypoint=True,
    ),
    "mips64el": RelaSpec(
        platform=PlatformSpec("MIPS64", "LITTLE"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("unicorn", "angr", "panda", "pcode"),
        string_source=StringSource(register="a0"),
        print_entrypoint=True,
    ),
    "mipsel": RelaSpec(
        platform=PlatformSpec("MIPS32", "LITTLE"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("unicorn", "angr", "panda", "pcode"),
        string_source=StringSource(register="a0"),
        print_entrypoint=True,
    ),
    "ppc": RelaSpec(
        platform=PlatformSpec("POWERPC32", "BIG"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("unicorn", "angr", "panda", "pcode"),
        string_source=StringSource(register="r3"),
        print_entrypoint=True,
    ),
    "ppc64": RelaSpec(
        platform=PlatformSpec("POWERPC64", "BIG"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("unicorn", "angr", "pcode"),
        string_source=StringSource(register="r3"),
        function_descriptor_entrypoint=True,
        print_entrypoint=True,
    ),
    "riscv64": RelaSpec(
        platform=PlatformSpec("RISCV64", "LITTLE"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("unicorn", "angr", "pcode"),
        string_source=StringSource(register="a0"),
        load_address=0x80000000,
        print_entrypoint=True,
    ),
    "tricore": RelaSpec(
        platform=PlatformSpec("TRICORE", "LITTLE"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("angr", "panda", "pcode"),
        string_source=StringSource(register="a4"),
        print_entrypoint=True,
    ),
}


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "rela":
        return False
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


def _prepare_stack(smallworld, machine, platform, arch: str, engine: str):
    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x8000, 0x4000)
    machine.add(stack)

    if arch in {"mips", "mipsel"}:
        stack.push_integer(0x7FFFFFF8, 4, "Arg Slot 2")
        stack.push_integer(0x7FFFFFF8, 4, "Arg Slot 1")
    elif arch == "ppc" and engine != "panda":
        stack.push_integer(0, 4, None)
        stack.push_integer(0, 4, None)
    elif arch in {"mips64", "mips64el", "la64", "riscv64", "ppc64"}:
        stack.push_integer(0x7FFFFFF8, 8, "fake return address")
    elif arch in {"armhf", "ppc"} and engine == "panda":
        stack.push_integer(0xFFFFFFFF, 4, "fake return address")

    return stack


def _configure_exit(
    machine, emulator, cpu, code, stack, arch: str, engine: str, entrypoint: int
) -> None:
    if arch == "armhf" and engine == "panda":
        emulator.add_exit_point(entrypoint + 40)
        return
    if arch == "ppc" and engine == "panda":
        emulator.add_exit_point(entrypoint + 68)
        return

    exitpoint = entrypoint + code.get_symbol_size("main")
    machine.add_exit_point(exitpoint)

    if arch == "amd64":
        stack.push_integer(exitpoint, 8, None)
    elif arch in {"i386", "m68k"}:
        stack.push_integer(exitpoint, 4, None)
    elif arch in {"aarch64", "armel", "armhf", "ppc", "ppc64"}:
        set_register(cpu, "lr", exitpoint)
    elif arch in {"la64", "mips", "mips64", "mips64el", "mipsel", "riscv64", "tricore"}:
        set_register(cpu, "ra", exitpoint)


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

    code = load_elf_code(
        smallworld,
        "rela",
        arch,
        platform,
        address=spec.load_address,
    )
    machine.add(code)

    if spec.function_descriptor_entrypoint:
        entrypoint = resolve_ppc64_function_descriptor(code, "main")
    else:
        entrypoint = code.get_symbol_value("main")
    if spec.print_entrypoint:
        print(f"Entrypoint {hex(entrypoint)}")
    set_register(cpu, spec.pc_register, entrypoint)

    stack = _prepare_stack(smallworld, machine, platform, arch, engine)

    machine.add(
        make_puts_model(
            smallworld,
            platform=platform,
            address=0x10000,
            source=spec.string_source,
        )
    )
    code.update_symbol_value("puts", 0x10000)

    if arch in {"mips", "mipsel", "mips64", "mips64el"}:
        set_register(cpu, "t9", entrypoint)
    if arch == "ppc64":
        set_register(cpu, "r2", 0x10027F00)

    emulator = make_emulator(smallworld, platform, engine)
    maybe_enable_linear(smallworld, emulator, engine)
    _configure_exit(machine, emulator, cpu, code, stack, arch, engine, entrypoint)
    set_register(cpu, spec.stack_pointer_register, stack.get_pointer())

    machine.emulate(emulator)
    return 0
