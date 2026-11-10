"""PowerPC guest kernels and encoding tables for the testfloat scenario.

Floating-point arithmetic on PowerPC is one A-form word::

    primary[0:5] | FRT[6:10] | FRA[11:15] | FRB[16:20] | FRC[21:25] | XO[26:30] | Rc

The primary opcode selects single precision (59) from double (63), and XO
selects the operation: fdiv 18, fsub 20, fadd 21, fsqrt 22, fmul 25.  Multiply
takes its second operand in FRC rather than FRB, which is the one irregularity
in the tables below.  fabs and fneg are X-form, exist only under primary 63,
and act on the register bits, so the single-precision loop uses them as-is.

32- and 64-bit PowerPC share these encodings and the kernel source, so one
table serves both; only the platform and engines differ.

The kernel installs the FPSCR mode itself (``mtfsfi``), so there is nothing to
seed: round to nearest with ties to even, non-IEEE mode off so subnormals stay
live, and every exception enable clear.
"""

from __future__ import annotations

from typing import Dict, Optional

from ..common import PlatformSpec
from .base import (
    ANGR_NO_SCALAR_SQRT,
    ENTRY_F32_BINARY,
    ENTRY_F32_UNARY,
    ENTRY_F64_BINARY,
    ENTRY_F64_UNARY,
    GHIDRA_FLUSHES_SUBNORMALS,
    ArchSupport,
    Kernel,
    TestFloatSpec,
    encode_patch,
)

# Patch words spelled most significant byte first, as the ISA writes them;
# PowerPC is big-endian here, so these are also memory order.
#
# The binary loops hold operand b in f1, so FRB = 1 (FRC = 1 for multiply);
# the unary loops name only FRT/FRB, both 0.
BINARY_PATCHES_SINGLE = {
    "add": bytes.fromhex("ec00082a"),  # fadds f0, f0, f1
    "sub": bytes.fromhex("ec000828"),  # fsubs f0, f0, f1
    "mul": bytes.fromhex("ec000072"),  # fmuls f0, f0, f1
    "div": bytes.fromhex("ec000824"),  # fdivs f0, f0, f1
}

UNARY_PATCHES_SINGLE = {
    "sqrt": bytes.fromhex("ec00002c"),  # fsqrts f0, f0
    "abs": bytes.fromhex("fc000210"),  # fabs   f0, f0
    "neg": bytes.fromhex("fc000050"),  # fneg   f0, f0
}

EXPECT_BINARY_SINGLE = {
    "add": "fadds f0, f0, f1",
    "sub": "fsubs f0, f0, f1",
    "mul": "fmuls f0, f0, f1",
    "div": "fdivs f0, f0, f1",
}

EXPECT_UNARY_SINGLE = {
    "sqrt": "fsqrts f0, f0",
    "abs": "fabs f0, f0",
    "neg": "fneg f0, f0",
}

# The same words under primary opcode 63: 0xEC... -> 0xFC...
BINARY_PATCHES_DOUBLE = {
    "add": bytes.fromhex("fc00082a"),  # fadd f0, f0, f1
    "sub": bytes.fromhex("fc000828"),  # fsub f0, f0, f1
    "mul": bytes.fromhex("fc000072"),  # fmul f0, f0, f1
    "div": bytes.fromhex("fc000824"),  # fdiv f0, f0, f1
}

UNARY_PATCHES_DOUBLE = {
    "sqrt": bytes.fromhex("fc00002c"),  # fsqrt f0, f0
    "abs": bytes.fromhex("fc000210"),  # fabs  f0, f0
    "neg": bytes.fromhex("fc000050"),  # fneg  f0, f0
}

EXPECT_BINARY_DOUBLE = {
    "add": "fadd f0, f0, f1",
    "sub": "fsub f0, f0, f1",
    "mul": "fmul f0, f0, f1",
    "div": "fdiv f0, f0, f1",
}

EXPECT_UNARY_DOUBLE = {
    "sqrt": "fsqrt f0, f0",
    "abs": "fabs f0, f0",
    "neg": "fneg f0, f0",
}


def _big(table: Dict[str, bytes]) -> Dict[str, bytes]:
    return {op: encode_patch(word, big=True) for op, word in table.items()}


# Every loop opens with two mtfsfi and an mtctr, so the arithmetic sits at
# entry + 4 * (3 + operand loads).
KERNELS: Dict[str, Kernel] = {
    "f32_binary": Kernel(
        ENTRY_F32_BINARY,
        ENTRY_F32_BINARY + 20,
        _big(BINARY_PATCHES_SINGLE),
        expect=EXPECT_BINARY_SINGLE,
    ),
    "f32_unary": Kernel(
        ENTRY_F32_UNARY,
        ENTRY_F32_UNARY + 16,
        _big(UNARY_PATCHES_SINGLE),
        expect=EXPECT_UNARY_SINGLE,
    ),
    "f64_binary": Kernel(
        ENTRY_F64_BINARY,
        ENTRY_F64_BINARY + 20,
        _big(BINARY_PATCHES_DOUBLE),
        expect=EXPECT_BINARY_DOUBLE,
    ),
    "f64_unary": Kernel(
        ENTRY_F64_UNARY,
        ENTRY_F64_UNARY + 16,
        _big(UNARY_PATCHES_DOUBLE),
        expect=EXPECT_UNARY_DOUBLE,
    ),
}

# QEMU's system-mode reset leaves MSR[FP] clear, so every loop would fault on
# its first `lfs`/`lfd`; PandaEmulator's PowerPC machine definition sets it.
# ppc.panda is measured locally; ppc64.panda only in CI, since the local PANDA
# predates the configurable machine for ppc64.
_ENGINES = ("unicorn", "angr", "pcode", "panda")

SPECS: Dict[str, TestFloatSpec] = {
    "ppc": TestFloatSpec(
        platform=PlatformSpec("POWERPC32", "BIG"),
        engines=_ENGINES,
        in_register="r3",
        out_register="r4",
        count_register="r5",
        setup={},
        kernels=KERNELS,
    ),
    "ppc64": TestFloatSpec(
        platform=PlatformSpec("POWERPC64", "BIG"),
        engines=_ENGINES,
        in_register="r3",
        out_register="r4",
        count_register="r5",
        setup={},
        kernels=KERNELS,
    ),
}


# PowerPC single-precision arithmetic computes in the double-format FPRs and
# rounds once, so VEX lifts `fadds` and its siblings to Iop_AddF64r32 (and
# SubF64r32, MulF64r32, DivF64r32), and `stfs` to Iop_TruncF64asF32.  angr's
# irop.py implements none of them: the arithmetic raises UnsupportedIROpError
# "Operation not implemented" and the store "no calculate function identified
# for Iop_TruncF64asF32".  Checked by lifting the f32 loops with pyvex and
# asking vexop_to_simop for every op in them; everything else is implemented,
# and the double-precision loops pass.
ANGR_NO_PPC_SINGLE = (
    "angr's VEX engine implements neither Iop_*F64r32 (PowerPC single-precision "
    "arithmetic) nor Iop_TruncF64asF32 (stfs) (upstream)"
)


# PANDA's `ppc32` CPU is a PowerPC 604, which, like the real part, lacks the
# optional square-root instructions: QEMU gates fsqrt and fsqrts on
# PPC_FLOAT_FSQRT, which its 604 model doesn't set, so both decode as invalid
# (reported as Panda exception 96).  The ppc64 POWER8 has them.  Measured on
# the local PANDA, where the other eight functions pass.
PANDA_604_NO_FSQRT = (
    "PANDA's ppc32 CPU is a PowerPC 604, which lacks the optional fsqrt and "
    "fsqrts instructions"
)


def function_skip(arch: str, engine: str, func: str) -> Optional[str]:
    if arch == "ppc" and engine == "panda" and func.endswith("_sqrt"):
        return PANDA_604_NO_FSQRT
    if engine == "angr":
        if func.startswith("f32_"):
            return ANGR_NO_PPC_SINGLE
        if func.endswith("_sqrt"):
            return ANGR_NO_SCALAR_SQRT
    # The same Ghidra defect the other architectures record: 0x00000001 *
    # 0x7E000001 gives 0 where the reference, and Unicorn, give 0x00000001.
    if func in {"f32_mul", "f32_div"} and engine == "pcode":
        return GHIDRA_FLUSHES_SUBNORMALS
    return None


SUPPORT = ArchSupport(specs=SPECS, function_skip=function_skip)

__all__ = ["SUPPORT", "SPECS"]
