"""AArch64 guest kernels and encoding tables for the testfloat scenario.

Scalar floating-point data processing on AArch64 is one fixed 32-bit word.  The
two-source form is::

    0001 1110 | type[23:22] | 1 | Rm[20:16] | opcode[15:12] | 10 | Rn | Rd

so fadd/fsub/fmul/fdiv differ only in ``opcode`` (0010/0011/0000/0001), and the
one-source form (FSQRT/FABS/FNEG) differs only in bits [20:15].  In both,
``type`` selects single (00) from double (01), which is why each precision needs
its own table: a single-precision word dropped into the double-precision loop is
still a *legal* instruction that quietly computes in the wrong precision on the
wrong register file, so nothing crashes - the answers are just wrong.  Every
entry below came from the assembler's own output rather than being derived by
hand, and --check-patches re-disassembles them against ``expect``.

FPCR is installed by the kernel itself (``msr fpcr, xzr``) rather than seeded
here.  Two reasons: FPCR's reset value is architecturally UNKNOWN, and angr's
AArch64 machdef does not map ``fpcr``, so a harness-side write raises
UnsupportedRegisterError.  Zero is exactly the mode TestFloat verifies against -
RMode (bits 23:22) = 00, round to nearest with ties to even; FZ (bit 24) and
FZ16 (bit 19) clear so subnormals stay live, since flush-to-zero would fail
every gradual-underflow case; DN (bit 25) and AHP (bit 26) clear.

Styx is absent from ``engines`` because it has no AArch64 target at all
(``ConfigurationError`` from the machdef), not because of any defect here.
"""

from __future__ import annotations

from typing import Dict, Optional

from ..common import PlatformSpec
from .base import (
    ENTRY_F32_BINARY,
    ENTRY_F32_UNARY,
    ENTRY_F64_BINARY,
    ENTRY_F64_UNARY,
    GHIDRA_FLUSHES_SUBNORMALS,
    ArchSupport,
    Kernel,
    TestFloatSpec,
    kernel_key,
)

# Patch words in *memory* order.  AArch64 is little-endian, so these read
# byte-reversed against the word form a disassembler prints: FADD S0,S0,S1 is
# the word 0x1E212800, stored as 00 28 21 1E.  base.encode_patch is deliberately
# not used - it exists for tables spelled most-significant-byte-first.
#
# The binary loops hold operand b in S1/D1, so Rm = 1; the unary loops name only
# Rd/Rn, both 0.
BINARY_PATCHES_SINGLE = {
    "add": bytes.fromhex("0028211e"),  # 1e212800 fadd s0, s0, s1
    "sub": bytes.fromhex("0038211e"),  # 1e213800 fsub s0, s0, s1
    "mul": bytes.fromhex("0008211e"),  # 1e210800 fmul s0, s0, s1
    "div": bytes.fromhex("0018211e"),  # 1e211800 fdiv s0, s0, s1
}

UNARY_PATCHES_SINGLE = {
    "sqrt": bytes.fromhex("00c0211e"),  # 1e21c000 fsqrt s0, s0
    "abs": bytes.fromhex("00c0201e"),  # 1e20c000 fabs  s0, s0
    "neg": bytes.fromhex("0040211e"),  # 1e214000 fneg  s0, s0
}

# What each patch must disassemble to, checked by the scenario's
# --check-patches. The operands matter more than the mnemonic here: unlike
# SuperH, an AArch64 opcode carries its own precision, so a single-precision
# word in the double-precision loop still decodes cleanly - as `s0, s0, s1`
# against a kernel that loaded d0/d1 - and only the register spelling gives it
# away.
EXPECT_BINARY_SINGLE = {
    "add": "fadd s0, s0, s1",
    "sub": "fsub s0, s0, s1",
    "mul": "fmul s0, s0, s1",
    "div": "fdiv s0, s0, s1",
}

EXPECT_UNARY_SINGLE = {
    "sqrt": "fsqrt s0, s0",
    "abs": "fabs s0, s0",
    "neg": "fneg s0, s0",
}

# The same opcodes with type = 01, i.e. bit 22 set: 0x1E21xxxx -> 0x1E61xxxx.
BINARY_PATCHES_DOUBLE = {
    "add": bytes.fromhex("0028611e"),  # 1e612800 fadd d0, d0, d1
    "sub": bytes.fromhex("0038611e"),  # 1e613800 fsub d0, d0, d1
    "mul": bytes.fromhex("0008611e"),  # 1e610800 fmul d0, d0, d1
    "div": bytes.fromhex("0018611e"),  # 1e611800 fdiv d0, d0, d1
}

UNARY_PATCHES_DOUBLE = {
    "sqrt": bytes.fromhex("00c0611e"),  # 1e61c000 fsqrt d0, d0
    "abs": bytes.fromhex("00c0601e"),  # 1e60c000 fabs  d0, d0
    "neg": bytes.fromhex("0040611e"),  # 1e614000 fneg  d0, d0
}

EXPECT_BINARY_DOUBLE = {
    "add": "fadd d0, d0, d1",
    "sub": "fsub d0, d0, d1",
    "mul": "fmul d0, d0, d1",
    "div": "fdiv d0, d0, d1",
}

EXPECT_UNARY_DOUBLE = {
    "sqrt": "fsqrt d0, d0",
    "abs": "fabs d0, d0",
    "neg": "fneg d0, d0",
}

# Every AArch64 instruction is four bytes and every loop opens with one `msr
# fpcr, xzr`, so the arithmetic sits at entry + 4 * (1 + operand loads).
KERNELS: Dict[str, Kernel] = {
    "f32_binary": Kernel(
        ENTRY_F32_BINARY,
        ENTRY_F32_BINARY + 12,
        BINARY_PATCHES_SINGLE,
        expect=EXPECT_BINARY_SINGLE,
    ),
    "f32_unary": Kernel(
        ENTRY_F32_UNARY,
        ENTRY_F32_UNARY + 8,
        UNARY_PATCHES_SINGLE,
        expect=EXPECT_UNARY_SINGLE,
    ),
    "f64_binary": Kernel(
        ENTRY_F64_BINARY,
        ENTRY_F64_BINARY + 12,
        BINARY_PATCHES_DOUBLE,
        expect=EXPECT_BINARY_DOUBLE,
    ),
    "f64_unary": Kernel(
        ENTRY_F64_UNARY,
        ENTRY_F64_UNARY + 8,
        UNARY_PATCHES_DOUBLE,
        expect=EXPECT_UNARY_DOUBLE,
    ),
}

SPECS: Dict[str, TestFloatSpec] = {
    "aarch64": TestFloatSpec(
        platform=PlatformSpec("AARCH64", "LITTLE"),
        engines=("unicorn", "angr", "panda", "pcode"),
        in_register="x0",
        out_register="x1",
        count_register="x2",
        # Nothing to seed: precision is encoded in the instruction rather than
        # in a control register, and the kernel installs FPCR itself.
        setup={},
        kernels=KERNELS,
    ),
}

# angr's VEX engine implements no square root at all: irop.py has no Sqrt
# calculate function of any kind (only _op_fgeneric_RSqrtEst, the estimate), so
# lifting FSQRT raises UnsupportedIROpError "no calculate function identified for
# Iop_SqrtF32"/"...F64" before any arithmetic happens.  That is upstream angr and
# hits every VEX architecture, not just this one; the four basic operations on
# the same operands all pass, so it is a missing op rather than a wrong answer.
ANGR_NO_SQRT = "angr's VEX engine has no Iop_Sqrt implementation (upstream)"


def function_skip(arch: str, engine: str, func: str) -> Optional[str]:
    if func.endswith("_sqrt") and engine == "angr":
        return ANGR_NO_SQRT
    # Reproduced independently of SuperH, on a sleigh that shares no code with
    # it: 0x00000001 * 0x3F000001 and 0x00000001 / 0x3F800001 both yield 0 under
    # `pcode` where unicorn, panda and the reference all return 0x00000001. Same
    # backend defect, so the shared reason applies; double precision is fine.
    if func in {"f32_mul", "f32_div"} and engine == "pcode":
        return GHIDRA_FLUSHES_SUBNORMALS
    return None


SUPPORT = ArchSupport(specs=SPECS, function_skip=function_skip)

__all__ = ["SUPPORT", "SPECS", "kernel_key"]
