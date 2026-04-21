from __future__ import annotations

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
class StackCaseSpec:
    platform: PlatformSpec
    pc_register: str
    result_register: str
    engines: tuple[str, ...]
    register_arguments: tuple[tuple[str, int], ...] = ()
    stack_arguments: tuple[tuple[int, int], ...] = ()
    stack_pointer_register: str = "sp"
    stack_pointer_adjust: int = 0
    add_stack_guard: bool = True


_SPECS = {
    "aarch64": StackCaseSpec(
        platform=PlatformSpec("AARCH64", "LITTLE"),
        pc_register="pc",
        result_register="x0",
        engines=("unicorn", "angr", "panda", "pcode"),
        register_arguments=(
            ("w0", 0x11111111),
            ("w1", 0x01010101),
            ("w2", 0x22222222),
            ("w3", 0x01010101),
            ("w4", 0x33333333),
            ("w5", 0x01010101),
            ("w6", 0x44444444),
            ("w7", 0x01010101),
        ),
        stack_arguments=((0x55555555, 8),),
    ),
    "amd64": StackCaseSpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pc_register="rip",
        result_register="eax",
        engines=("unicorn", "angr", "panda", "pcode"),
        register_arguments=(
            ("rdi", 0x11111111),
            ("rdx", 0x22222222),
            ("r8", 0x33333333),
        ),
        stack_arguments=((0x44444444, 8), (0xFFFFFFFF, 8)),
        stack_pointer_register="rsp",
    ),
    "armel": StackCaseSpec(
        platform=PlatformSpec("ARM_V5T", "LITTLE"),
        pc_register="pc",
        result_register="r0",
        engines=("unicorn", "angr", "panda", "pcode"),
        register_arguments=(
            ("r0", 0x11111111),
            ("r1", 0x01010101),
            ("r2", 0x22222222),
            ("r3", 0x01010101),
        ),
        stack_arguments=((0x44444444, 4), (0x01010101, 4), (0x33333333, 4)),
    ),
    "armhf": StackCaseSpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pc_register="pc",
        result_register="r0",
        engines=("unicorn", "angr", "panda", "pcode"),
        register_arguments=(
            ("r0", 0x11111111),
            ("r1", 0x01010101),
            ("r2", 0x22222222),
            ("r3", 0x01010101),
        ),
        stack_arguments=((0x44444444, 4), (0x01010101, 4), (0x33333333, 4)),
    ),
    "i386": StackCaseSpec(
        platform=PlatformSpec("X86_32", "LITTLE"),
        pc_register="eip",
        result_register="eax",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack_arguments=(
            (0x44444444, 4),
            (0x01010101, 4),
            (0x33333333, 4),
            (0x01010101, 4),
            (0x22222222, 4),
            (0x01010101, 4),
            (0x11111111, 4),
            (0x01010101, 4),
        ),
        stack_pointer_register="esp",
    ),
    "la64": StackCaseSpec(
        platform=PlatformSpec("LOONGARCH64", "LITTLE"),
        pc_register="pc",
        result_register="a0",
        engines=("angr", "pcode"),
        register_arguments=(
            ("a0", 0x1111),
            ("a1", 0x01010101),
            ("a2", 0x2222),
            ("a3", 0x01010101),
            ("a4", 0x3333),
            ("a5", 0x01010101),
            ("a6", 0x4444),
            ("a7", 0x01010101),
        ),
        stack_arguments=((0x5555, 4), (0x01010101, 4)),
        add_stack_guard=False,
    ),
    "m68k": StackCaseSpec(
        platform=PlatformSpec("M68K", "BIG"),
        pc_register="pc",
        result_register="d0",
        engines=("unicorn", "pcode"),
        stack_arguments=(
            (0x44444444, 4),
            (0x01010101, 4),
            (0x33333333, 4),
            (0x01010101, 4),
            (0x22222222, 4),
            (0x01010101, 4),
            (0x11111111, 4),
            (0x01010101, 4),
        ),
    ),
    "mips": StackCaseSpec(
        platform=PlatformSpec("MIPS32", "BIG"),
        pc_register="pc",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        register_arguments=(
            ("a0", 0x1111),
            ("a1", 0x01010101),
            ("a2", 0x2222),
            ("a3", 0x01010101),
        ),
        stack_arguments=(
            (0x4444, 4),
            (0x01010101, 4),
            (0x3333, 4),
            (0x01010101, 4),
            (0x01010101, 4),
            (0x01010101, 4),
            (0x01010101, 4),
        ),
    ),
    "mipsel": StackCaseSpec(
        platform=PlatformSpec("MIPS32", "LITTLE"),
        pc_register="pc",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        register_arguments=(
            ("a0", 0x1111),
            ("a1", 0x01010101),
            ("a2", 0x2222),
            ("a3", 0x01010101),
        ),
        stack_arguments=(
            (0x4444, 4),
            (0x01010101, 4),
            (0x3333, 4),
            (0x01010101, 4),
            (0x01010101, 4),
            (0x01010101, 4),
            (0x01010101, 4),
        ),
    ),
    "mips64": StackCaseSpec(
        platform=PlatformSpec("MIPS64", "BIG"),
        pc_register="pc",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        register_arguments=(
            ("a0", 0x1111),
            ("a1", 0x01010101),
            ("a2", 0x2222),
            ("a3", 0x01010101),
            ("a4", 0x3333),
            ("a5", 0x01010101),
            ("a6", 0x4444),
            ("a7", 0x01010101),
        ),
        stack_arguments=((0x5555, 4), (0x01010101, 4)),
    ),
    "mips64el": StackCaseSpec(
        platform=PlatformSpec("MIPS64", "LITTLE"),
        pc_register="pc",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        register_arguments=(
            ("a0", 0x1111),
            ("a1", 0x01010101),
            ("a2", 0x2222),
            ("a3", 0x01010101),
            ("a4", 0x3333),
            ("a5", 0x01010101),
            ("a6", 0x4444),
            ("a7", 0x01010101),
        ),
        stack_arguments=((0x5555, 4), (0x01010101, 4)),
    ),
    "ppc": StackCaseSpec(
        platform=PlatformSpec("POWERPC32", "BIG"),
        pc_register="pc",
        result_register="r3",
        engines=("unicorn", "angr", "panda", "pcode"),
        register_arguments=(
            ("r3", 0x1111),
            ("r4", 0x01010101),
            ("r5", 0x2222),
            ("r6", 0x01010101),
            ("r7", 0x3333),
            ("r8", 0x01010101),
            ("r9", 0x4444),
            ("r10", 0x01010101),
        ),
        stack_arguments=((0x5555, 4),),
        stack_pointer_adjust=-24,
    ),
    "ppc64": StackCaseSpec(
        platform=PlatformSpec("POWERPC64", "BIG"),
        pc_register="pc",
        result_register="r3",
        engines=("unicorn", "angr", "pcode"),
        register_arguments=(
            ("r3", 0x1111),
            ("r4", 0x01010101),
            ("r5", 0x2222),
            ("r6", 0x01010101),
            ("r7", 0x3333),
            ("r8", 0x01010101),
            ("r9", 0x4444),
            ("r10", 0x01010101),
        ),
        stack_arguments=((0x5555, 8),),
        stack_pointer_adjust=-116,
    ),
    "riscv64": StackCaseSpec(
        platform=PlatformSpec("RISCV64", "LITTLE"),
        pc_register="pc",
        result_register="a0",
        engines=("unicorn", "angr", "pcode"),
        register_arguments=(
            ("a0", 0x11111111),
            ("a1", 0x01010101),
            ("a2", 0x22222222),
            ("a3", 0x01010101),
            ("a4", 0x33333333),
            ("a5", 0x01010101),
            ("a6", 0x44444444),
            ("a7", 0x01010101),
        ),
        stack_arguments=((0x55555555, 8),),
    ),
    "tricore": StackCaseSpec(
        platform=PlatformSpec("TRICORE", "LITTLE"),
        pc_register="pc",
        result_register="d2",
        engines=("angr", "panda", "pcode"),
        register_arguments=(
            ("d4", 0x11111111),
            ("d5", 0x01010101),
            ("d6", 0x22222222),
            ("d7", 0x01010101),
        ),
        stack_arguments=((0xCCCCCCCC, 4),),
    ),
    "xtensa": StackCaseSpec(
        platform=PlatformSpec("XTENSA", "LITTLE"),
        pc_register="pc",
        result_register="a2",
        engines=("angr", "pcode"),
        register_arguments=(
            ("a2", 0x11111111),
            ("a3", 0x01010101),
            ("a4", 0x22222222),
            ("a5", 0x01010101),
            ("a6", 0x33333333),
            ("a7", 0x01010101),
        ),
        stack_arguments=((0x44444444, 4),),
    ),
}


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "stack":
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

    code = load_raw_code(smallworld, "stack", arch)
    machine.add(code)
    set_register(cpu, spec.pc_register, code.address)

    stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
    machine.add(stack)

    for register, value in spec.register_arguments:
        set_register(cpu, register, value)

    for value, size in spec.stack_arguments:
        stack.push_integer(value, size, None)

    if spec.add_stack_guard:
        stack.write_bytes(0x2500, b"\xff\xff\xff\xff")

    set_register(
        cpu,
        spec.stack_pointer_register,
        stack.get_pointer() + spec.stack_pointer_adjust,
    )

    emulator = make_emulator(smallworld, platform, engine)
    maybe_enable_linear(smallworld, emulator, engine)
    emulator.add_exit_point(code.address + code.get_capacity())

    final_machine = machine.emulate(emulator)
    print(getattr(final_machine.get_cpu(), spec.result_register))
    return 0
