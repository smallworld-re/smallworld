"""SuperH guest kernels and encoding tables for the testfloat scenario.

Every SuperH FP operation shares the encoding 1111 nnnn mmmm iiii, so the
arithmetic instruction differs only in its low nibble: fadd f010, fsub f011,
fmul f012, fdiv f013; the unary forms are fsqrt f06d, fabs f05d, fneg f04d.
Verified by disassembly - see the scenario's --check-patches.

FPSCR: bits 0-1 are the rounding mode (00 = nearest-even, which is what
TestFloat verifies against by default, and *not* the SuperH reset value of 01),
bit 18 is DN (flush denormals - must stay 0 or every denormal case is wrong),
bit 19 is PR (double-precision arithmetic) and bit 20 is SZ (64-bit fmov).
Single needs all four clear; double needs PR and SZ.
"""

from __future__ import annotations

from typing import Dict, Mapping, Optional, Tuple

from ..common import PlatformSpec
from .base import (
    ANGR_NO_FP,
    ENTRY_F32_BINARY,
    ENTRY_F32_UNARY,
    ENTRY_F64_BINARY,
    ENTRY_F64_UNARY,
    GHIDRA_FLUSHES_SUBNORMALS,
    ArchSupport,
    Kernel,
    TestFloatSpec,
    encode_patch,
    kernel_key,
)

FPSCR_SINGLE = 0x00000000
FPSCR_DOUBLE = 0x00180000

# 1111 nnnn mmmm iiii. The single-precision loop keeps its operands in fr0/fr1,
# so m = 1.
BINARY_PATCHES = {
    "add": bytes.fromhex("f010"),
    "sub": bytes.fromhex("f011"),
    "mul": bytes.fromhex("f012"),
    "div": bytes.fromhex("f013"),
}

# The double-precision loop uses dr0/dr2, so m = 2. This table cannot be shared
# with the single-precision one: a DR pair must name an even register, and an
# odd m under FPSCR.PR is an illegal instruction (QEMU rejects it with
# `opcode & 0x0110`, and Ghidra's sleigh quietly reads DR0 instead, which looks
# like correct-but-wrong `a op a` arithmetic).
BINARY_PATCHES_DOUBLE = {
    "add": bytes.fromhex("f020"),
    "sub": bytes.fromhex("f021"),
    "mul": bytes.fromhex("f022"),
    "div": bytes.fromhex("f023"),
}

# Unary forms name only n, which is 0 in both loops, so one table serves both.
UNARY_PATCHES = {
    "sqrt": bytes.fromhex("f06d"),
    "abs": bytes.fromhex("f05d"),
    "neg": bytes.fromhex("f04d"),
}

# What each patch must disassemble to. A disassembler cannot know FPSCR.PR, so
# it spells the double-precision forms with `fr` names too -- which is why the
# register *numbers* carry the whole distinction here: fr1 is the second
# single-precision operand, while fr2 is the upper half of the dr2 pair
# (DRn = FRn:FRn+1, FRn upper -- see platforms.defs.superh.float_bank_registers).
# Pinning these is the point of the check; the fr1/fr2 confusion is a mistake
# that has already been made once in this scenario and produced believable
# arithmetic.
EXPECT_BINARY = {op: f"f{op} fr1,fr0" for op in BINARY_PATCHES}
EXPECT_BINARY_DOUBLE = {op: f"f{op} fr2,fr0" for op in BINARY_PATCHES_DOUBLE}
EXPECT_UNARY = {op: f"f{op} fr0" for op in UNARY_PATCHES}


def _kernels(big: bool) -> Dict[str, Kernel]:
    """The four loops, with patch bytes ordered for the target.

    The tables above spell opcodes the way the SuperH manual does, most
    significant byte first, but a little-endian build stores each 16-bit
    instruction byte-swapped -- writing the manual's bytes verbatim into an
    sh4el image decodes as a completely different instruction. Swapping here
    rather than in the shared harness keeps the rule with the ISA it belongs to;
    architectures whose manuals already list bytes in memory order (x86) must
    not be swapped at all.

    Offsets are past the two-byte `lds r7, fpscr` prologue: binary loops load
    two operands before the arithmetic (+6), unary loops one (+4).
    """

    def order(table: Mapping[str, bytes]) -> Dict[str, bytes]:
        return {op: encode_patch(patch, big) for op, patch in table.items()}

    return {
        "f32_binary": Kernel(
            ENTRY_F32_BINARY,
            ENTRY_F32_BINARY + 6,
            order(BINARY_PATCHES),
            EXPECT_BINARY,
        ),
        "f32_unary": Kernel(
            ENTRY_F32_UNARY,
            ENTRY_F32_UNARY + 4,
            order(UNARY_PATCHES),
            EXPECT_UNARY,
        ),
        "f64_binary": Kernel(
            ENTRY_F64_BINARY,
            ENTRY_F64_BINARY + 6,
            order(BINARY_PATCHES_DOUBLE),
            EXPECT_BINARY_DOUBLE,
        ),
        "f64_unary": Kernel(
            ENTRY_F64_UNARY,
            ENTRY_F64_UNARY + 4,
            order(UNARY_PATCHES),
            EXPECT_UNARY,
        ),
    }


def _spec(platform: PlatformSpec, engines: Tuple[str, ...]) -> TestFloatSpec:
    return TestFloatSpec(
        platform=platform,
        engines=engines,
        in_register="r4",
        out_register="r5",
        count_register="r6",
        # FPSCR arrives in r7 and the kernel installs it with `lds`. Writing the
        # fpscr register directly leaves SH-4's split PR/SZ/RM pseudo-registers
        # stale, which silently downgrades every double-precision op to single.
        setup={
            "f32": {"r7": FPSCR_SINGLE},
            "f64": {"r7": FPSCR_DOUBLE},
        },
        kernels=_kernels(platform.byteorder == "BIG"),
    )


_ENGINES = ("pcode", "angr", "panda", "styx")

SPECS: Dict[str, TestFloatSpec] = {
    "sh2a": _spec(PlatformSpec("SUPERH_SH2A_FPU", "BIG"), _ENGINES),
    "sh4": _spec(PlatformSpec("SUPERH_SH4", "BIG"), _ENGINES),
    "sh4el": _spec(PlatformSpec("SUPERH_SH4", "LITTLE"), _ENGINES),
}

# Ghidra's SH-2A sleigh defines FP_PR and then never reads it, so double
# precision silently runs single-precision arithmetic on the operands' upper
# halves -- with SZ ignored as well, the kernel loads four bytes into fr0, four
# into fr2, adds single and stores four. Styx bundles the same spec.
_SH2A_NO_DOUBLE = (
    "Ghidra's SH-2A sleigh ignores FPSCR.PR (single-precision only); "
    "Styx bundles the same spec"
)


def function_skip(arch: str, engine: str, func: str) -> Optional[str]:
    if func.startswith("f64") and engine in {"pcode", "styx"} and arch == "sh2a":
        return _SH2A_NO_DOUBLE
    if func in {"f32_mul", "f32_div"} and engine == "pcode":
        return GHIDRA_FLUSHES_SUBNORMALS
    return None


SUPPORT = ArchSupport(
    specs=SPECS,
    variant_skips={f"{arch}.angr": ANGR_NO_FP for arch in SPECS},
    function_skip=function_skip,
)

__all__ = ["SUPPORT", "SPECS", "kernel_key"]
