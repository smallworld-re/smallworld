from __future__ import annotations

from typing import Sequence

from .common import PlatformSpec
from .raw_binary import RawBinarySpec, run_integer_case, supports_variant

# Branch is the same scenario logic everywhere; only the machine metadata and
# the register we print at the end vary by architecture.
_SPECS = {
    "aarch64": RawBinarySpec(
        platform=PlatformSpec("AARCH64", "LITTLE"),
        pc_register="pc",
        arg_register="x0",
        result_register="w0",
        engines=("unicorn", "angr", "panda", "pcode"),
        print_mode="register",
    ),
    "amd64": RawBinarySpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pc_register="rip",
        arg_register="rdi",
        result_register="eax",
        engines=("unicorn", "angr", "panda", "pcode"),
        print_mode="register",
    ),
    "armel": RawBinarySpec(
        platform=PlatformSpec("ARM_V5T", "LITTLE"),
        pc_register="pc",
        arg_register="r0",
        result_register="r0",
        engines=("unicorn", "angr", "panda", "pcode"),
        print_mode="register",
    ),
    "armhf": RawBinarySpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pc_register="pc",
        arg_register="r0",
        result_register="r0",
        engines=("unicorn", "angr", "panda", "pcode"),
        print_mode="register",
    ),
    "i386": RawBinarySpec(
        platform=PlatformSpec("X86_32", "LITTLE"),
        pc_register="eip",
        arg_register="edi",
        result_register="eax",
        engines=("unicorn", "angr", "panda", "pcode"),
        print_mode="register",
    ),
    "la64": RawBinarySpec(
        platform=PlatformSpec("LOONGARCH64", "LITTLE"),
        pc_register="pc",
        arg_register="a0",
        result_register="a0",
        engines=("angr", "pcode"),
        print_mode="register",
    ),
    "m68k": RawBinarySpec(
        platform=PlatformSpec("M68K", "BIG"),
        pc_register="pc",
        arg_register="d0",
        result_register="d0",
        engines=("unicorn", "pcode"),
        print_mode="register",
    ),
    "mips": RawBinarySpec(
        platform=PlatformSpec("MIPS32", "BIG"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        print_mode="register",
    ),
    "mipsel": RawBinarySpec(
        platform=PlatformSpec("MIPS32", "LITTLE"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        print_mode="register",
    ),
    "mips64": RawBinarySpec(
        platform=PlatformSpec("MIPS64", "BIG"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        print_mode="register",
    ),
    "mips64el": RawBinarySpec(
        platform=PlatformSpec("MIPS64", "LITTLE"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
        print_mode="register",
    ),
    "msp430": RawBinarySpec(
        platform=PlatformSpec("MSP430", "LITTLE"),
        pc_register="pc",
        arg_register="r15",
        result_register="r14",
        engines=("pcode",),
        print_mode="register",
    ),
    "msp430x": RawBinarySpec(
        platform=PlatformSpec("MSP430X", "LITTLE"),
        pc_register="pc",
        arg_register="r15",
        result_register="r14",
        engines=("angr", "pcode"),
        print_mode="register",
    ),
    "ppc": RawBinarySpec(
        platform=PlatformSpec("POWERPC32", "BIG"),
        pc_register="pc",
        arg_register="r3",
        result_register="r3",
        engines=("unicorn", "angr", "panda", "pcode"),
        print_mode="register",
    ),
    "ppc64": RawBinarySpec(
        platform=PlatformSpec("POWERPC64", "BIG"),
        pc_register="pc",
        arg_register="r3",
        result_register="r3",
        engines=("unicorn", "angr", "pcode"),
        print_mode="register",
    ),
    "riscv64": RawBinarySpec(
        platform=PlatformSpec("RISCV64", "LITTLE"),
        pc_register="pc",
        arg_register="a0",
        result_register="a0",
        engines=("unicorn", "angr", "pcode"),
        print_mode="register",
    ),
    "xtensa": RawBinarySpec(
        platform=PlatformSpec("XTENSA", "LITTLE"),
        pc_register="pc",
        arg_register="a2",
        result_register="a2",
        engines=("angr", "pcode"),
        print_mode="register",
    ),
}


def can_run(scenario: str, variant: str) -> bool:
    return scenario == "branch" and supports_variant(variant, _SPECS)


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    return run_integer_case("branch", variant, args, _SPECS)
