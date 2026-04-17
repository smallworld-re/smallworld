from __future__ import annotations

from typing import Sequence

from .common import PlatformSpec
from .raw_binary import RawBinarySpec, run_integer_case, supports_variant

# These raw-binary families are mostly "same test, different registers".
# Keeping the matrix as data is much easier to read than dozens of tiny files.
_SPECS = {
    "aarch64": RawBinarySpec(
        platform=PlatformSpec("AARCH64", "LITTLE"),
        pc_register="pc",
        arg_register="x0",
        result_register="x0",
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "amd64": RawBinarySpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        pc_register="rip",
        arg_register="rdi",
        result_register="eax",
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "armel": RawBinarySpec(
        platform=PlatformSpec("ARM_V5T", "LITTLE"),
        pc_register="pc",
        arg_register="r0",
        result_register="r0",
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "armhf": RawBinarySpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        pc_register="pc",
        arg_register="r0",
        result_register="r0",
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "i386": RawBinarySpec(
        platform=PlatformSpec("X86_32", "LITTLE"),
        pc_register="eip",
        arg_register="edi",
        result_register="eax",
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "la64": RawBinarySpec(
        platform=PlatformSpec("LOONGARCH64", "LITTLE"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        engines=("angr", "pcode"),
    ),
    "m68k": RawBinarySpec(
        platform=PlatformSpec("M68K", "BIG"),
        pc_register="pc",
        arg_register="d0",
        result_register="d0",
        engines=("unicorn", "pcode"),
    ),
    "mips": RawBinarySpec(
        platform=PlatformSpec("MIPS32", "BIG"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "mipsel": RawBinarySpec(
        platform=PlatformSpec("MIPS32", "LITTLE"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "mips64": RawBinarySpec(
        platform=PlatformSpec("MIPS64", "BIG"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "mips64el": RawBinarySpec(
        platform=PlatformSpec("MIPS64", "LITTLE"),
        pc_register="pc",
        arg_register="a0",
        result_register="v0",
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "msp430": RawBinarySpec(
        platform=PlatformSpec("MSP430", "LITTLE"),
        pc_register="pc",
        arg_register="r15",
        result_register="r14",
        engines=("pcode",),
    ),
    "msp430x": RawBinarySpec(
        platform=PlatformSpec("MSP430X", "LITTLE"),
        pc_register="pc",
        arg_register="r15",
        result_register="r14",
        engines=("angr", "pcode"),
    ),
    "ppc": RawBinarySpec(
        platform=PlatformSpec("POWERPC32", "BIG"),
        pc_register="pc",
        arg_register="r3",
        result_register="r3",
        engines=("unicorn", "angr", "panda", "pcode"),
    ),
    "ppc64": RawBinarySpec(
        platform=PlatformSpec("POWERPC64", "BIG"),
        pc_register="pc",
        arg_register="r3",
        result_register="r3",
        engines=("unicorn", "angr", "pcode"),
    ),
    "riscv64": RawBinarySpec(
        platform=PlatformSpec("RISCV64", "LITTLE"),
        pc_register="pc",
        arg_register="a0",
        result_register="a0",
        engines=("unicorn", "angr", "pcode"),
    ),
    "tricore": RawBinarySpec(
        platform=PlatformSpec("TRICORE", "LITTLE"),
        pc_register="pc",
        arg_register="d4",
        result_register="d2",
        engines=("angr", "pcode"),
    ),
    "xtensa": RawBinarySpec(
        platform=PlatformSpec("XTENSA", "LITTLE"),
        pc_register="pc",
        arg_register="a2",
        result_register="a2",
        engines=("angr", "pcode"),
    ),
}

_SPECIAL_VARIANTS = {
    "ppc.panda": RawBinarySpec(
        platform=PlatformSpec("POWERPC32", "BIG"),
        pc_register="pc",
        arg_register="r3",
        result_register="r3",
        engines=("panda",),
        print_exit_point=True,
    )
}


def can_run(scenario: str, variant: str) -> bool:
    if scenario != "square":
        return False
    if variant in _SPECIAL_VARIANTS:
        return True
    return supports_variant(variant, _SPECS)


def run_case(scenario: str, variant: str, args: Sequence[str]) -> int:
    if variant in _SPECIAL_VARIANTS:
        return run_integer_case(
            "square", variant, args, {"ppc": _SPECIAL_VARIANTS[variant]}
        )
    return run_integer_case("square", variant, args, _SPECS)
