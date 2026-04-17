from __future__ import annotations

from typing import Sequence

from .common import PlatformSpec
from .raw_binary import RawBinarySpec, StackSpec, run_integer_case, supports_variant

# `call` is the same raw binary on every architecture, but call setup differs:
# most platforms need a fake return address, while i386 also passes the first
# argument on the stack instead of in a register.
_STACK_32 = StackSpec(pointer_register="sp", fake_return_size=4)
_STACK_64 = StackSpec(pointer_register="sp", fake_return_size=8)

_SPECS = {
    "aarch64": RawBinarySpec(
        platform=PlatformSpec("AARCH64", "LITTLE"),
        pc_register="pc",
        arg_register="x0",
        result_register="x0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack=_STACK_64,
    ),
    "amd64": RawBinarySpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pc_register="rip",
        arg_register="rdi",
        result_register="eax",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack=StackSpec(pointer_register="rsp", fake_return_size=8),
    ),
    "armel": RawBinarySpec(
        platform=PlatformSpec("ARM_V5T", "LITTLE"),
        pc_register="pc",
        arg_register="r0",
        result_register="r0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack=_STACK_32,
    ),
    "armhf": RawBinarySpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pc_register="pc",
        arg_register="r0",
        result_register="r0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack=_STACK_32,
    ),
    "i386": RawBinarySpec(
        platform=PlatformSpec("X86_32", "LITTLE"),
        pc_register="eip",
        result_register="eax",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack=StackSpec(
            pointer_register="esp",
            fake_return_size=4,
            argument_size=4,
            pointer_adjust=4,
        ),
    ),
    "la64": RawBinarySpec(
        platform=PlatformSpec("LOONGARCH64", "LITTLE"),
        pc_register="pc",
        arg_register="a0",
        result_register="a0",
        engines=("angr", "pcode"),
        stack=_STACK_64,
    ),
    "m68k": RawBinarySpec(
        platform=PlatformSpec("M68K", "BIG"),
        pc_register="pc",
        arg_register="d0",
        result_register="d0",
        engines=("unicorn", "pcode"),
        stack=_STACK_32,
    ),
    "mips": RawBinarySpec(
        platform=PlatformSpec("MIPS32", "BIG"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack=_STACK_32,
    ),
    "mipsel": RawBinarySpec(
        platform=PlatformSpec("MIPS32", "LITTLE"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack=_STACK_32,
    ),
    "mips64": RawBinarySpec(
        platform=PlatformSpec("MIPS64", "BIG"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack=_STACK_64,
    ),
    "mips64el": RawBinarySpec(
        platform=PlatformSpec("MIPS64", "LITTLE"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack=_STACK_64,
    ),
    "ppc": RawBinarySpec(
        platform=PlatformSpec("POWERPC32", "BIG"),
        pc_register="pc",
        arg_register="r3",
        result_register="r3",
        engines=("unicorn", "angr", "panda", "pcode"),
        stack=_STACK_32,
    ),
    "ppc64": RawBinarySpec(
        platform=PlatformSpec("POWERPC64", "BIG"),
        pc_register="pc",
        arg_register="r3",
        result_register="r3",
        engines=("unicorn", "angr", "pcode"),
        stack=_STACK_64,
    ),
    "riscv64": RawBinarySpec(
        platform=PlatformSpec("RISCV64", "LITTLE"),
        pc_register="pc",
        arg_register="a0",
        result_register="a0",
        engines=("unicorn", "angr", "pcode"),
        stack=_STACK_64,
    ),
    "tricore": RawBinarySpec(
        platform=PlatformSpec("TRICORE", "LITTLE"),
        pc_register="pc",
        arg_register="d4",
        result_register="d2",
        engines=("angr", "pcode"),
        stack=StackSpec(pointer_register="sp", fake_return_size=None),
    ),
    "xtensa": RawBinarySpec(
        platform=PlatformSpec("XTENSA", "LITTLE"),
        pc_register="pc",
        arg_register="a2",
        result_register="a2",
        engines=("angr", "pcode"),
    ),
}


def can_run(scenario: str, variant: str) -> bool:
    return scenario == "call" and supports_variant(variant, _SPECS)


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    return run_integer_case("call", variant, args, _SPECS)
