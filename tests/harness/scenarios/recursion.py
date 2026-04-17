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
class StackItem:
    value: int | str
    size: int
    label: str | None = None


@dataclasses.dataclass(frozen=True)
class RecursionSpec:
    platform: PlatformSpec
    pc_register: str
    result_register: str
    engines: tuple[str, ...]
    arg_register: str | None = None
    stack_pointer_register: str = "sp"
    stack_items: tuple[StackItem, ...] = ()
    stack_pointer_adjust: int = 0


_SPECS = {
    "aarch64": RecursionSpec(
        platform=PlatformSpec("AARCH64", "LITTLE"),
        pc_register="pc",
        arg_register="x0",
        result_register="x0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_items=(StackItem(0xFFFFFFFF, 8, "fake return address"),),
        stack_pointer_adjust=8,
    ),
    "amd64": RecursionSpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pc_register="rip",
        arg_register="rdi",
        result_register="eax",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_pointer_register="rsp",
        stack_items=(StackItem(0xFFFFFFFF, 8, "fake return address"),),
    ),
    "armel": RecursionSpec(
        platform=PlatformSpec("ARM_V5T", "LITTLE"),
        pc_register="pc",
        arg_register="r0",
        result_register="r0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_items=(StackItem(0xFFFFFFFF, 4, "fake return address"),),
    ),
    "armhf": RecursionSpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pc_register="pc",
        arg_register="r0",
        result_register="r0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_items=(StackItem(0xFFFFFFFF, 4, "fake return address"),),
    ),
    "i386": RecursionSpec(
        platform=PlatformSpec("X86_32", "LITTLE"),
        pc_register="eip",
        result_register="eax",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_pointer_register="esp",
        stack_items=(
            StackItem("argument", 4),
            StackItem(0xFFFFFFFF, 4, "fake return address"),
        ),
    ),
    "la64": RecursionSpec(
        platform=PlatformSpec("LOONGARCH64", "LITTLE"),
        pc_register="pc",
        arg_register="a0",
        result_register="a0",
        engines=("angr", "pcode"),
        stack_items=(StackItem(0xFFFFFFFF, 8, "fake return address"),),
    ),
    "m68k": RecursionSpec(
        platform=PlatformSpec("M68K", "BIG"),
        pc_register="pc",
        result_register="d0",
        engines=("unicorn", "pcode"),
        stack_items=(
            StackItem("argument", 4),
            StackItem(0xFFFFFFFF, 4, "fake return address"),
        ),
    ),
    "mips": RecursionSpec(
        platform=PlatformSpec("MIPS32", "BIG"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_items=(StackItem(0xFFFFFFFF, 4, "fake return address"),),
    ),
    "mipsel": RecursionSpec(
        platform=PlatformSpec("MIPS32", "LITTLE"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_items=(StackItem(0xFFFFFFFF, 4, "fake return address"),),
    ),
    "mips64": RecursionSpec(
        platform=PlatformSpec("MIPS64", "BIG"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_items=(StackItem(0xFFFFFFFF, 8, "fake return address"),),
    ),
    "mips64el": RecursionSpec(
        platform=PlatformSpec("MIPS64", "LITTLE"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_items=(StackItem(0xFFFFFFFF, 8, "fake return address"),),
    ),
    "ppc": RecursionSpec(
        platform=PlatformSpec("POWERPC32", "BIG"),
        pc_register="pc",
        arg_register="r3",
        result_register="r3",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_items=(
            StackItem(0xFFFFFFFF, 4, "placeholder for lr"),
            StackItem(0xFFFFFFFF, 4, "empty space"),
        ),
    ),
    "ppc64": RecursionSpec(
        platform=PlatformSpec("POWERPC64", "BIG"),
        pc_register="pc",
        arg_register="r3",
        result_register="r3",
        engines=("unicorn", "angr", "pcode"),
        stack_items=(StackItem(0xFFFFFFFF, 8, "fake return address"),),
        stack_pointer_adjust=-0x80,
    ),
    "riscv64": RecursionSpec(
        platform=PlatformSpec("RISCV64", "LITTLE"),
        pc_register="pc",
        arg_register="a0",
        result_register="a0",
        engines=("unicorn", "angr", "pcode"),
        stack_items=(StackItem(0xFFFFFFFF, 8, "fake return address"),),
        stack_pointer_adjust=8,
    ),
    "tricore": RecursionSpec(
        platform=PlatformSpec("TRICORE", "LITTLE"),
        pc_register="pc",
        arg_register="d4",
        result_register="d2",
        engines=("angr", "pcode"),
    ),
    "xtensa": RecursionSpec(
        platform=PlatformSpec("XTENSA", "LITTLE"),
        pc_register="pc",
        arg_register="a2",
        result_register="a2",
        engines=("angr", "pcode"),
        stack_items=(StackItem(0xFFFFFFFF, 4, "fake return address"),),
    ),
}


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "recursion":
        return False
    arch, engine = split_variant(variant)
    return arch in _SPECS and engine in _SPECS[arch].engines


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog=f"run_case.py {scenario} {variant}")
    parser.add_argument("value", type=lambda text: int(text, 0), help="numeric input")
    ns = parser.parse_args(list(args))

    import smallworld

    arch, engine = split_variant(variant)
    spec = _SPECS[arch]

    smallworld.logging.setup_logging(level=logging.INFO)

    platform = make_platform(smallworld, spec.platform)
    machine = smallworld.state.Machine()
    cpu = smallworld.state.cpus.CPU.for_platform(platform)
    machine.add(cpu)

    code = load_raw_code(smallworld, "recursion", arch)
    machine.add(code)
    set_register(cpu, spec.pc_register, code.address)

    if spec.arg_register is not None:
        set_register(cpu, spec.arg_register, ns.value)

    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
    machine.add(stack)
    for item in spec.stack_items:
        value = ns.value if item.value == "argument" else item.value
        stack.push_integer(value, item.size, item.label)
    set_register(
        cpu,
        spec.stack_pointer_register,
        stack.get_pointer() + spec.stack_pointer_adjust,
    )

    emulator = make_emulator(smallworld, platform, engine)
    maybe_enable_linear(smallworld, emulator, engine)
    emulator.add_exit_point(code.address + code.get_capacity())
    final_cpu = machine.emulate(emulator).get_cpu()
    print(hex(getattr(final_cpu, spec.result_register).get()))
    return 0
