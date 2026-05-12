from __future__ import annotations

import dataclasses
import logging
from typing import Sequence

from .common import (
    PlatformSpec,
    add_code_bounds,
    load_elf_code,
    load_elf_library,
    make_emulator,
    make_platform,
    maybe_enable_linear,
    push_cli_argv,
    set_register,
    split_variant,
)


@dataclasses.dataclass(frozen=True)
class LinkElfSpec:
    platform: PlatformSpec
    pointer_size: int
    pc_register: str
    stack_pointer_register: str
    result_register: str
    engines: tuple[str, ...]
    code_address: int | None = None
    lib_address: int | None = None
    argument_registers: tuple[str, str] | None = None
    use_platform_loader: bool = True
    add_zero_exitpoint: bool = False


_SPECS = {
    "aarch64": LinkElfSpec(
        platform=PlatformSpec("AARCH64", "LITTLE"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="sp",
        result_register="x0",
        engines=("unicorn", "angr", "panda", "pcode"),
        code_address=0x400000,
        lib_address=0x800000,
        argument_registers=("x0", "x1"),
        add_zero_exitpoint=True,
    ),
    "amd64": LinkElfSpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pointer_size=8,
        pc_register="rip",
        stack_pointer_register="rsp",
        result_register="rax",
        engines=("unicorn", "angr", "panda", "pcode"),
        code_address=0x400000,
        lib_address=0x800000,
        argument_registers=("rdi", "rsi"),
        add_zero_exitpoint=True,
    ),
    "armel": LinkElfSpec(
        platform=PlatformSpec("ARM_V6M", "LITTLE"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        result_register="r0",
        engines=("unicorn", "angr", "panda", "pcode"),
        lib_address=0x800000,
        argument_registers=("r0", "r1"),
        add_zero_exitpoint=True,
    ),
    "armhf": LinkElfSpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        result_register="r0",
        engines=("unicorn", "angr", "panda", "pcode"),
        code_address=0x400000,
        lib_address=0x800000,
        argument_registers=("r0", "r1"),
        add_zero_exitpoint=True,
    ),
    "i386": LinkElfSpec(
        platform=PlatformSpec("X86_32", "LITTLE"),
        pointer_size=4,
        pc_register="eip",
        stack_pointer_register="esp",
        result_register="eax",
        engines=("unicorn", "angr", "panda", "pcode"),
        code_address=0x400000,
        lib_address=0x800000,
        add_zero_exitpoint=True,
    ),
    "la64": LinkElfSpec(
        platform=PlatformSpec("LOONGARCH64", "LITTLE"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="sp",
        result_register="a0",
        engines=("angr", "pcode"),
        lib_address=0x400000,
        argument_registers=("a0", "a1"),
        add_zero_exitpoint=True,
    ),
    "m68k": LinkElfSpec(
        platform=PlatformSpec("M68K", "BIG"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        result_register="d0",
        engines=("unicorn", "pcode"),
        code_address=0x40000,
        lib_address=0x80000,
    ),
    "mips": LinkElfSpec(
        platform=PlatformSpec("MIPS32", "BIG"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        lib_address=0x800000,
        argument_registers=("a0", "a1"),
    ),
    "mipsel": LinkElfSpec(
        platform=PlatformSpec("MIPS32", "LITTLE"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        lib_address=0x800000,
        argument_registers=("a0", "a1"),
    ),
    "ppc": LinkElfSpec(
        platform=PlatformSpec("POWERPC32", "BIG"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="r1",
        result_register="r3",
        engines=("unicorn", "angr", "panda", "pcode"),
        lib_address=0x800000,
        argument_registers=("r3", "r4"),
        add_zero_exitpoint=True,
    ),
    "riscv64": LinkElfSpec(
        platform=PlatformSpec("RISCV64", "LITTLE"),
        pointer_size=8,
        pc_register="pc",
        stack_pointer_register="sp",
        result_register="a0",
        engines=("unicorn", "angr", "pcode"),
        code_address=0x400000,
        lib_address=0x800000,
        argument_registers=("a0", "a1"),
        add_zero_exitpoint=True,
    ),
    "tricore": LinkElfSpec(
        platform=PlatformSpec("TRICORE", "LITTLE"),
        pointer_size=4,
        pc_register="pc",
        stack_pointer_register="sp",
        result_register="d2",
        engines=("angr", "panda", "pcode"),
        argument_registers=("d4", "a4"),
    ),
}

_SKIP_REASONS = {
    "mips64": "Unexpected failure",
    "mips64.angr": "Unexpected failure",
    "mips64.panda": "Unexpected failure",
    "mips64.pcode": "Unexpected failure",
    "mips64el": "Unexpected failure",
    "mips64el.angr": "Unexpected failure",
    "mips64el.panda": "Unexpected failure",
    "mips64el.pcode": "Unexpected failure",
    "ppc64": "This test case doesn't work.",
    "ppc64.angr": "This test case doesn't work.",
    "ppc64.pcode": "This test case doesn't work.",
}


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "link_elf":
        return False
    if variant in _SKIP_REASONS:
        return True
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


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
        "link_elf",
        arch,
        platform,
        address=spec.code_address,
        use_platform=spec.use_platform_loader,
    )
    machine.add(code)
    lib = load_elf_library(
        smallworld,
        "link_elf",
        arch,
        platform,
        address=spec.lib_address,
        use_platform=spec.use_platform_loader,
    )
    machine.add(lib)

    lib.link_elf(lib)
    code.link_elf(code)
    lib.link_elf(lib, all_syms=True)
    code.link_elf(code, all_syms=True)
    code.link_elf(lib)

    entrypoint = code.get_symbol_value("main")
    set_register(cpu, spec.pc_register, entrypoint)

    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
    machine.add(stack)
    string_address, argv = push_cli_argv(stack, args[0], pointer_size=spec.pointer_size)

    exitpoint = entrypoint + code.get_symbol_size("main")
    if arch == "amd64":
        stack.push_integer(exitpoint, 8, None)
        machine.add_exit_point(exitpoint)
    elif arch in {"i386", "m68k"}:
        stack.push_integer(exitpoint, 4, None)
        machine.add_exit_point(exitpoint)
    elif arch in {"aarch64", "armel", "armhf", "ppc"}:
        set_register(cpu, "lr", exitpoint)
        machine.add_exit_point(exitpoint)
    elif arch in {"la64", "mips", "mipsel", "riscv64", "tricore"}:
        set_register(cpu, "ra", exitpoint)
        machine.add_exit_point(exitpoint)

    set_register(cpu, spec.stack_pointer_register, stack.get_pointer())
    if spec.argument_registers is not None:
        argc_register, argv_register = spec.argument_registers
        set_register(cpu, argc_register, 2)
        set_register(cpu, argv_register, argv)
    if arch in {"mips", "mipsel"}:
        set_register(cpu, "t9", entrypoint)
    if arch == "ppc":
        if 0x70000000 not in lib._dtags:
            raise ValueError("No DT_PPC_GOT in dtags")
        set_register(cpu, "r30", lib._dtags[0x70000000] + lib.address)
    if arch == "m68k":
        print(f"str_addr: {string_address:x}")

    emulator = make_emulator(smallworld, platform, engine)
    maybe_enable_linear(smallworld, emulator, engine)
    if spec.add_zero_exitpoint:
        emulator.add_exit_point(0)
    add_code_bounds(machine, code, lib)

    final_cpu = machine.emulate(emulator).get_cpu()
    print(hex(getattr(final_cpu, spec.result_register).get()))
    return 0
