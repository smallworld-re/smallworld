"""i386 guest kernels and encoding tables for the testfloat scenario.

The kernels use **SSE scalar** arithmetic, not x87.  x87 evaluates on a stack of
80-bit extended registers, and its reset control word selects the 64-bit
significand, so an f32 or f64 add rounds once into the extended format and again
on store.  That double rounding differs from IEEE single-rounding on exactly the
operands TestFloat is built to generate, which would make every backend look
broken for a reason that has nothing to do with the emulator.  SSE computes at
the operand's own width, which is the model SoftFloat implements.
``docs/concepts/platforms/float_support.csv`` records ``i386 x87`` as unsupported
and ``i386 sse`` as supported on that basis.

Encodings.  The SSE scalar arithmetic ops share the shape
``<prefix> 0F <op> <modrm>``: ``F3`` selects single precision and ``F2`` double,
and the opcode byte is 58 add / 5C sub / 59 mul / 5E div / 51 sqrt.  The single-
and double-precision tables are therefore the same four bytes with one prefix
changed, and every patch is four bytes wide - the same length, landing on the
same instruction boundary, which is what makes one blob serve five operations on
a variable-length ISA.  x86 opcode bytes are listed by the manual in the order
they appear in memory, so the tables below are used verbatim; ``encode_patch``
(which reverses big-endian-spelled fixed-width words for SuperH) must *not* be
applied here or the prefix would end up last.  Every byte string below was read
out of ``objdump -d`` on the assembled instruction, and the scenario's
``--check-patches`` re-disassembles them in place.

MXCSR.  TestFloat's reference is round-to-nearest-even with denormals live.
Nothing is seeded for it, because measurement showed nothing needs to be:

* ``stmxcsr`` under unicorn and under Ghidra's p-code emulator both store
  ``0x00000000`` - RC=00 (nearest-even), FTZ=0 and DAZ=0, i.e. the three fields
  that change results are already right.  (The architectural reset value is
  0x1F80; both backends model the exception *mask* bits as clear instead, which
  only matters if a backend traps unmasked SIMD exceptions.  None observed does,
  and the scenario does not compare exception flags anyway.)
* angr cannot execute ``stmxcsr`` at all - VEX lowers it to the ccall
  ``x86g_create_mxcsr``, which smallworld's angr bridge rejects with
  ``EmulationError: Unsupported ccall`` - so its mode was established from the
  results instead: all ten functions verify bit-exactly, including the subnormal
  and tie cases, which only holds for RNE with denormals live.  VEX models only
  the rounding field (``guest_SSEROUND``, default nearest) and ignores FTZ/DAZ
  entirely, so there is nothing there to get wrong.

So no ``ldmxcsr`` prologue: the entry offset is the top of the loop, unlike
SuperH where FPSCR has to be installed first because its reset rounding mode is
toward zero.  Adding one would also cost angr the whole architecture, since VEX
lowers ``ldmxcsr`` to the ccall ``x86g_check_ldmxcsr`` the same way.
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

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

# Both loops keep operand a in xmm0 and operand b in xmm1 and write the result
# back to xmm0, so the modrm byte is C1 for the binary forms; the unary forms
# read and write xmm0, so C0. `abs` and `neg` have no SSE instruction - they are
# bit tricks against a mask constant (andps/xorps), which needs a loaded operand
# rather than a one-instruction patch - so they are left out and the runner
# reports "no encoding" if ever asked for them.
BINARY_PATCHES_F32 = {
    "add": bytes.fromhex("f30f58c1"),  # addss %xmm1,%xmm0
    "sub": bytes.fromhex("f30f5cc1"),  # subss %xmm1,%xmm0
    "mul": bytes.fromhex("f30f59c1"),  # mulss %xmm1,%xmm0
    "div": bytes.fromhex("f30f5ec1"),  # divss %xmm1,%xmm0
}

UNARY_PATCHES_F32 = {
    "sqrt": bytes.fromhex("f30f51c0"),  # sqrtss %xmm0,%xmm0
}

# Same bytes with the F2 prefix. Unlike SuperH, where a double operand must name
# an even register and an odd field is an illegal instruction, x86 selects the
# width from the prefix alone - so the register fields are identical and only the
# first byte distinguishes these tables from the ones above.
BINARY_PATCHES_F64 = {
    "add": bytes.fromhex("f20f58c1"),  # addsd %xmm1,%xmm0
    "sub": bytes.fromhex("f20f5cc1"),  # subsd %xmm1,%xmm0
    "mul": bytes.fromhex("f20f59c1"),  # mulsd %xmm1,%xmm0
    "div": bytes.fromhex("f20f5ec1"),  # divsd %xmm1,%xmm0
}

UNARY_PATCHES_F64 = {
    "sqrt": bytes.fromhex("f20f51c0"),  # sqrtsd %xmm0,%xmm0
}

# What each patch must disassemble to. Capstone prints x86 in Intel syntax,
# destination first, so these read in the opposite operand order from the AT&T
# source in testfloat.i386.s: `addss %xmm1,%xmm0` there is `addss xmm0, xmm1`
# here. The operand half is what catches a patch aimed at the wrong loop - the
# f32 and f64 tables differ only in a prefix byte, so a double-precision patch
# dropped into the single-precision loop would still decode to a plausible
# instruction and only the `ss`/`sd` suffix gives it away.
EXPECT_BINARY_F32 = {op: f"{op}ss xmm0, xmm1" for op in BINARY_PATCHES_F32}
EXPECT_UNARY_F32 = {op: f"{op}ss xmm0, xmm0" for op in UNARY_PATCHES_F32}
EXPECT_BINARY_F64 = {op: f"{op}sd xmm0, xmm1" for op in BINARY_PATCHES_F64}
EXPECT_UNARY_F64 = {op: f"{op}sd xmm0, xmm0" for op in UNARY_PATCHES_F64}

# x86 has no post-increment addressing, so the cursors advance with explicit adds
# after the store and the patched instruction sits at a fixed distance from the
# entry: past two operand loads (4 + 5 bytes, the second load carrying a
# displacement byte) in the binary loops, past one (4 bytes) in the unary ones.
_BINARY_PATCH = 9
_UNARY_PATCH = 4

KERNELS: Dict[str, Kernel] = {
    "f32_binary": Kernel(
        ENTRY_F32_BINARY,
        ENTRY_F32_BINARY + _BINARY_PATCH,
        BINARY_PATCHES_F32,
        EXPECT_BINARY_F32,
    ),
    "f32_unary": Kernel(
        ENTRY_F32_UNARY,
        ENTRY_F32_UNARY + _UNARY_PATCH,
        UNARY_PATCHES_F32,
        EXPECT_UNARY_F32,
    ),
    "f64_binary": Kernel(
        ENTRY_F64_BINARY,
        ENTRY_F64_BINARY + _BINARY_PATCH,
        BINARY_PATCHES_F64,
        EXPECT_BINARY_F64,
    ),
    "f64_unary": Kernel(
        ENTRY_F64_UNARY,
        ENTRY_F64_UNARY + _UNARY_PATCH,
        UNARY_PATCHES_F64,
        EXPECT_UNARY_F64,
    ),
}

# Styx is absent because it has no i386 target at all: StyxMachineDef.for_platform
# raises ConfigurationError for X86_32, so there is no variant to list. PANDA is
# listed and skipped instead, because it does load and run i386 code - it just
# cannot run this code (see _PANDA_NO_SSE).
_ENGINES: Tuple[str, ...] = ("unicorn", "angr", "pcode", "panda")

SPECS: Dict[str, TestFloatSpec] = {
    "i386": TestFloatSpec(
        platform=PlatformSpec("X86_32", "LITTLE"),
        engines=_ENGINES,
        in_register="esi",
        out_register="edi",
        count_register="ecx",
        # Nothing to seed: MXCSR already reads as round-to-nearest-even with
        # FTZ/DAZ clear on every backend measured, and smallworld's X86_32 CPU
        # state does not model MXCSR as a register anyway, so it could only be
        # reached through an `ldmxcsr` in the kernel.
        setup={},
        kernels=KERNELS,
    ),
}

# PANDA's i386 machine leaves SSE unavailable, so the first SSE instruction the
# kernel executes raises #UD. Minimal case: a blob of just
# `movsd (%esi),%xmm0` (f2 0f 10 06) aborts with "Panda exception 6"
# (EXCP06_ILLOP), while `movl (%esi),%eax; movl %eax,(%edi)` on the same setup
# runs and stores the right word - so i386 itself works there and only the SSE
# unit is missing. Consistent with docs/concepts/platforms/float_support.csv,
# which records i386 sse as unsupported on panda.
_PANDA_NO_SSE = (
    "PANDA's i386 CPU has no usable SSE: `movsd (%esi),%xmm0` alone raises "
    "#UD (Panda exception 6) while integer loads/stores run fine"
)


def function_skip(arch: str, engine: str, func: str) -> Optional[str]:
    """Which (engine, function) cells cannot pass, and why.

    ``GHIDRA_FLUSHES_SUBNORMALS`` reproduces here on the *same operand pair*
    base.py cites for SuperH: running the f32_binary kernel on 0x00000001 *
    0x3F000001 gives 0x00000000 under pcode and the correct 0x00000001 under
    unicorn from the identical blob.  Across 2000 generated cases the failures are
    only ever that shape - f32_mul 20 errors, f32_div 10 errors, every one
    "=> +-0.000000 ...ux, expected +-0.000001" - and f64 is clean.  Two unrelated
    sleighs flushing gradual underflow the same way in the same two operations
    puts the defect in Ghidra's float evaluation rather than in either ISA's
    specification.

    ``ANGR_NO_FP`` deliberately does *not* appear: it describes angr's *p-code*
    engine, and i386 angr is VEX-backed, which does implement FP.
    """
    if func in {"f32_mul", "f32_div"} and engine == "pcode":
        return GHIDRA_FLUSHES_SUBNORMALS
    return None


SUPPORT = ArchSupport(
    specs=SPECS,
    variant_skips={"i386.panda": _PANDA_NO_SSE},
    function_skip=function_skip,
)

__all__ = ["SUPPORT", "SPECS", "kernel_key"]
