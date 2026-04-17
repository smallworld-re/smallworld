from __future__ import annotations

import dataclasses
import logging
from typing import Sequence

from .common import (
    PlatformSpec,
    add_code_bounds,
    load_elf_code,
    make_emulator,
    make_platform,
    maybe_enable_linear,
    push_cli_argv,
    set_register,
    split_variant,
)


@dataclasses.dataclass(frozen=True)
class ElfSpec:
    platform: PlatformSpec
    pointer_size: int
    pc_register: str
    stack_pointer_register: str
    engines: tuple[str, ...]
    print_register: str | None = None
    use_platform_loader: bool = True


_SPECS = {
    "aarch64": ElfSpec(
        platform=PlatformSpec("AARCH64", "LITTLE"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "amd64": ElfSpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pointer_size=8,
        pc_register="rip",
        stack_pointer_register="rsp",
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "armel": ElfSpec(
        platform=PlatformSpec("ARM_V6M", "LITTLE"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "armhf": ElfSpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "i386": ElfSpec(
        platform=PlatformSpec("X86_32", "LITTLE"),
        pointer_size=4,
        pc_register="eip",
        stack_pointer_register="esp",
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "la64": ElfSpec(
        platform=PlatformSpec("LOONGARCH64", "LITTLE"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("angr", "pcode"),
    ),
    "m68k": ElfSpec(
        platform=PlatformSpec("M68K", "BIG"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("unicorn", "pcode"),
    ),
    "mips": ElfSpec(
        platform=PlatformSpec("MIPS32", "BIG"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "mips64": ElfSpec(
        platform=PlatformSpec("MIPS64", "BIG"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "mips64el": ElfSpec(
        platform=PlatformSpec("MIPS64", "LITTLE"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "mipsel": ElfSpec(
        platform=PlatformSpec("MIPS32", "LITTLE"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "ppc": ElfSpec(
        platform=PlatformSpec("POWERPC32", "BIG"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="r1",
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "ppc64": ElfSpec(
        platform=PlatformSpec("POWERPC64", "BIG"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="r1",
        engines=("angr", "pcode"),
    ),
    "riscv64": ElfSpec(
        platform=PlatformSpec("RISCV64", "LITTLE"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("unicorn", "angr", "pcode"),
        print_register="a0",
        use_platform_loader=False,
    ),
    "tricore": ElfSpec(
        platform=PlatformSpec("TRICORE", "LITTLE"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("angr", "pcode"),
    ),
    "xtensa": ElfSpec(
        platform=PlatformSpec("XTENSA", "LITTLE"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        engines=("angr", "pcode"),
        print_register="a2",
        use_platform_loader=False,
    ),
}

_SKIP_REASONS = {
    "ppc64": "Unicorn ppc64 support buggy",
}

_UNICORN_BOUND_EXITS = {
    "aarch64": 0xAC,
    "armel": 0x88,
    "armhf": 0x88,
}


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "elf":
        return False
    if variant in _SKIP_REASONS:
        return True
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


def _configure_exitpoints(
    machine, emulator, cpu, code, stack, arch: str, engine: str
) -> None:
    entrypoint = code.entrypoint
    if entrypoint is None:
        raise ValueError("ELF has no entrypoint")

    if arch == "amd64":
        exitpoint = entrypoint + code.get_symbol_size("_start") - 4
        machine.add_exit_point(exitpoint)
        stack.push_integer(exitpoint, 8, None)
        if engine == "unicorn":
            emulator.add_exit_point(0)
        return

    if arch == "i386":
        if engine == "angr":
            exitpoint = entrypoint + code.get_symbol_size("_start")
            machine.add_exit_point(exitpoint)
            stack.push_integer(exitpoint, 4, None)
        else:
            exitpoint = entrypoint + code.get_symbol_size("_start") - 4
            machine.add_exit_point(exitpoint)
            stack.push_integer(exitpoint, 8, None)
        return

    if arch in {"aarch64", "armel", "armhf"} and engine == "panda":
        exitpoint = entrypoint + code.get_symbol_size("_start") - 4
        set_register(cpu, "lr", exitpoint)
        machine.add_exit_point(exitpoint)
        return

    if arch in _UNICORN_BOUND_EXITS and engine == "unicorn":
        emulator.add_exit_point(0)
        for start, _ in code.bounds:
            emulator.add_exit_point(start + _UNICORN_BOUND_EXITS[arch])
        return

    if arch == "m68k":
        stack.push_integer(0xFFFF0, 4, None)
        machine.add_exit_point(0xFFFF0)
        return

    if arch in {"mips", "mipsel"} and engine == "unicorn":
        set_register(cpu, "ra", 0xFFFF0)
        emulator.add_exit_point(0xFFFF0)
        return

    if arch in {"mips", "mipsel"} and engine == "panda":
        exitpoint = entrypoint + code.get_symbol_size("__start") - 4
        set_register(cpu, "ra", exitpoint)
        machine.add_exit_point(exitpoint)
        return

    if arch in {"mips64", "mips64el"} and engine == "unicorn":
        set_register(cpu, "ra", 0x10101010)
        machine.add_exit_point(0x10101010)
        return

    if arch in {"mips64", "mips64el"} and engine == "panda":
        emulator.add_exit_point(entrypoint + 0x3C)
        return

    if arch == "tricore":
        set_register(cpu, "ra", 0xFFFF0)
        machine.add_exit_point(0xFFFF0)
        return

    if arch == "ppc" and engine == "panda":
        machine.add_exit_point(entrypoint + 0x34)


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    if variant in _SKIP_REASONS:
        raise SystemExit(_SKIP_REASONS[variant])
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

    code = load_elf_code(
        smallworld,
        "elf",
        arch,
        platform,
        use_platform=spec.use_platform_loader,
    )
    machine.add(code)
    if code.entrypoint is None:
        raise ValueError("ELF has no entrypoint")
    set_register(cpu, spec.pc_register, code.entrypoint)

    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
    machine.add(stack)
    push_cli_argv(stack, args[0], pointer_size=spec.pointer_size)

    emulator = make_emulator(smallworld, platform, engine)
    maybe_enable_linear(smallworld, emulator, engine)
    add_code_bounds(machine, code)
    _configure_exitpoints(machine, emulator, cpu, code, stack, arch, engine)

    set_register(cpu, spec.stack_pointer_register, stack.get_pointer())
    final_machine = machine.emulate(emulator)

    if spec.print_register is not None:
        print(getattr(final_machine.get_cpu(), spec.print_register))
    return 0
