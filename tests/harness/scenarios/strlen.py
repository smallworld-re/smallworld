from __future__ import annotations

import argparse
import dataclasses
import logging
from typing import Sequence

from .common import (
    PlatformSpec,
    load_raw_code,
    make_emulator,
    make_platform,
    maybe_enable_linear,
    set_register,
    split_variant,
)


@dataclasses.dataclass(frozen=True)
class StrlenSpec:
    platform: PlatformSpec
    pc_register: str
    result_register: str
    engines: tuple[str, ...]
    stack_pointer_register: str
    return_address_size: int
    arg_register: str | None = None
    stack_argument_size: int | None = None
    print_stack: bool = False
    print_address: bool = False


_SPECS = {
    "aarch64": StrlenSpec(
        platform=PlatformSpec("AARCH64", "LITTLE"),
        pc_register="pc",
        result_register="x0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_pointer_register="sp",
        return_address_size=8,
        arg_register="x0",
    ),
    "amd64": StrlenSpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pc_register="rip",
        result_register="eax",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_pointer_register="rsp",
        return_address_size=8,
        arg_register="rdi",
        print_stack=True,
        print_address=True,
    ),
    "armel": StrlenSpec(
        platform=PlatformSpec("ARM_V5T", "LITTLE"),
        pc_register="pc",
        result_register="r0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_pointer_register="sp",
        return_address_size=4,
        arg_register="r0",
    ),
    "armhf": StrlenSpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pc_register="pc",
        result_register="r0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_pointer_register="sp",
        return_address_size=4,
        arg_register="r0",
    ),
    "i386": StrlenSpec(
        platform=PlatformSpec("X86_32", "LITTLE"),
        pc_register="eip",
        result_register="eax",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_pointer_register="esp",
        return_address_size=4,
        stack_argument_size=4,
    ),
    "la64": StrlenSpec(
        platform=PlatformSpec("LOONGARCH64", "LITTLE"),
        pc_register="pc",
        result_register="a0",
        engines=("angr", "pcode"),
        stack_pointer_register="sp",
        return_address_size=8,
        arg_register="a0",
    ),
    "m68k": StrlenSpec(
        platform=PlatformSpec("M68K", "BIG"),
        pc_register="pc",
        result_register="d0",
        engines=("unicorn", "pcode"),
        stack_pointer_register="sp",
        return_address_size=4,
        stack_argument_size=4,
    ),
    "mips": StrlenSpec(
        platform=PlatformSpec("MIPS32", "BIG"),
        pc_register="pc",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_pointer_register="sp",
        return_address_size=4,
        arg_register="a0",
    ),
    "mipsel": StrlenSpec(
        platform=PlatformSpec("MIPS32", "LITTLE"),
        pc_register="pc",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_pointer_register="sp",
        return_address_size=4,
        arg_register="a0",
    ),
    "mips64": StrlenSpec(
        platform=PlatformSpec("MIPS64", "BIG"),
        pc_register="pc",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_pointer_register="sp",
        return_address_size=8,
        arg_register="a0",
    ),
    "mips64el": StrlenSpec(
        platform=PlatformSpec("MIPS64", "LITTLE"),
        pc_register="pc",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_pointer_register="sp",
        return_address_size=8,
        arg_register="a0",
    ),
    "ppc": StrlenSpec(
        platform=PlatformSpec("POWERPC32", "BIG"),
        pc_register="pc",
        result_register="r3",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_pointer_register="sp",
        return_address_size=4,
        arg_register="r3",
    ),
    "ppc64": StrlenSpec(
        platform=PlatformSpec("POWERPC64", "BIG"),
        pc_register="pc",
        result_register="r3",
        engines=("unicorn", "angr", "pcode"),
        stack_pointer_register="sp",
        return_address_size=8,
        arg_register="r3",
    ),
    "riscv64": StrlenSpec(
        platform=PlatformSpec("RISCV64", "LITTLE"),
        pc_register="pc",
        result_register="a0",
        engines=("unicorn", "angr", "pcode"),
        stack_pointer_register="sp",
        return_address_size=8,
        arg_register="a0",
    ),
    "xtensa": StrlenSpec(
        platform=PlatformSpec("XTENSA", "LITTLE"),
        pc_register="pc",
        result_register="a2",
        engines=("angr", "pcode"),
        stack_pointer_register="sp",
        return_address_size=4,
        arg_register="a2",
    ),
}


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "strlen":
        return False
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog=f"run_case.py {scenario} {variant}")
    parser.add_argument("value", help="string input")
    ns = parser.parse_args(list(args))

    import smallworld

    arch, engine = split_variant(variant)
    spec = _SPECS[arch]

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, "strlen", arch)
    machine.add(code)
    set_register(cpu, spec.pc_register, code.address)

    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
    machine.add(stack)

    string = ns.value.encode("utf-8") + b"\0"
    padding = b"\0" * (16 - (len(string) % 16))
    stack.push_bytes(string + padding, None)
    if spec.print_stack:
        print(stack)

    saddr = stack.get_pointer()
    if spec.print_address:
        print(hex(saddr))

    if spec.stack_argument_size is not None:
        stack.push_integer(saddr, spec.stack_argument_size, None)

    stack.push_integer(0x00000000, spec.return_address_size, None)
    set_register(cpu, spec.stack_pointer_register, stack.get_pointer())

    if spec.arg_register is not None:
        set_register(cpu, spec.arg_register, saddr)

    emulator = make_emulator(smallworld, platform, engine)
    maybe_enable_linear(smallworld, emulator, engine)
    emulator.add_exit_point(code.address + code.get_capacity())

    final_machine = machine.emulate(emulator)
    print(hex(getattr(final_machine.get_cpu(), spec.result_register).get()))
    return 0
