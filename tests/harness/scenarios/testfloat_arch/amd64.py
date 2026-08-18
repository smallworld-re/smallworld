"""x86-64 guest kernels and encoding tables for the testfloat scenario.

The SSE scalar arithmetic instructions are laid out for exactly this kind of
patching: ``addss``/``subss``/``mulss``/``divss`` are ``F3 0F <op> C1`` and
differ only in the opcode byte (58/5C/59/5E), and the double-precision forms are
the same table under the ``F2`` prefix instead of ``F3``.  ``sqrtss``/``sqrtsd``
are opcode 51 with ``C0`` (xmm0 from xmm0), which is why they live in the unary
kernels: same length as the binary forms, different operand shape.

Bytes here are in *memory order*, which for x86 is also the order Intel's manual
lists them, so - unlike the fixed-width big-endian-spelled SuperH tables - they
must not be run through ``base.encode_patch``.  Every byte string below was read
out of ``objdump -M intel`` on a NASM-assembled probe rather than hand-derived;
the scenario's ``--check-patches`` re-disassembles them with capstone.

Length is load-bearing on a variable-length ISA: the harness overwrites exactly
``len(patch)`` bytes at ``patch_offset``, so a shorter replacement would leave a
tail of the old instruction behind and a longer one would eat the store that
follows.  All ten encodings below happen to be 4 bytes, and the kernels keep
their operands in xmm0/xmm1 so the ModRM byte is identical across precisions.

``abs``/``neg`` are deliberately absent.  x86 has no scalar FP absolute-value or
negate instruction; both are done with ``andps``/``xorps`` against a sign mask
held in a second register, which needs a constant pool the kernel does not have.
The harness skips any operation missing from the table, so the scenario simply
never asks for them here.

MXCSR needs no prologue.  TestFloat's reference is round-to-nearest-even with
denormals live, which is MXCSR.RC = 00, FTZ (bit 15) = 0 and DAZ (bit 6) = 0.
Read back with ``stmxcsr`` at kernel entry, unicorn and Ghidra hand the kernel
0x0000 and angr 0x1F80 - the three differ only in the exception *mask* bits
(0x1F80 is the architectural reset value, all six exceptions masked), and every
rounding and denormal control bit is already clear on all three.  So there is
nothing to seed, and ``setup`` stays empty; contrast SuperH, whose reset
rounding mode is round-to-zero and which therefore has to be handed an FPSCR.
Should a backend ever start with FTZ/DAZ set, the fix is a general register in
``setup`` plus an ``ldmxcsr`` prologue in the kernel - and every patch offset
below moves.
"""

from __future__ import annotations

from typing import Dict, Optional

from ..common import PlatformSpec
from .base import (
    ENTRY_F32_BINARY,
    ENTRY_F32_UNARY,
    ENTRY_F64_BINARY,
    ENTRY_F64_UNARY,
    ArchSupport,
    Kernel,
    TestFloatSpec,
    kernel_key,
)

# F3 0F <op> C1 -- scalar single, xmm0 <- xmm0 op xmm1.
BINARY_PATCHES_SINGLE = {
    "add": bytes.fromhex("f30f58c1"),
    "sub": bytes.fromhex("f30f5cc1"),
    "mul": bytes.fromhex("f30f59c1"),
    "div": bytes.fromhex("f30f5ec1"),
}

# F2 0F <op> C1 -- the same opcodes with the scalar-double prefix. Kept as a
# separate table rather than derived from the single one by prefix substitution:
# the prefix is what selects the operand *width*, so a table that computed it
# would be one edit away from silently running single-precision arithmetic on
# double operands - the failure mode that bit the SuperH kernels from the other
# direction.
BINARY_PATCHES_DOUBLE = {
    "add": bytes.fromhex("f20f58c1"),
    "sub": bytes.fromhex("f20f5cc1"),
    "mul": bytes.fromhex("f20f59c1"),
    "div": bytes.fromhex("f20f5ec1"),
}

# Unary: xmm0 <- op xmm0, so ModRM is C0 rather than C1.
UNARY_PATCHES_SINGLE = {"sqrt": bytes.fromhex("f30f51c0")}
UNARY_PATCHES_DOUBLE = {"sqrt": bytes.fromhex("f20f51c0")}

# What capstone must print for each patch. The operands matter as much as the
# mnemonic: `addss` and `addsd` differ by a single prefix byte, so a table entry
# that drifted between precisions would still disassemble as a plausible
# instruction, and the xmm0/xmm1 pair is what proves the patch is operating on
# the operands the loop actually loaded rather than on xmm0 twice.
EXPECT_BINARY_SINGLE = {op: f"{op}ss xmm0, xmm1" for op in BINARY_PATCHES_SINGLE}
EXPECT_BINARY_DOUBLE = {op: f"{op}sd xmm0, xmm1" for op in BINARY_PATCHES_DOUBLE}
EXPECT_UNARY_SINGLE = {"sqrt": "sqrtss xmm0, xmm0"}
EXPECT_UNARY_DOUBLE = {"sqrt": "sqrtsd xmm0, xmm0"}

# Bytes of loop preamble before the arithmetic, from
# `objdump -D -b binary -m i386:x86-64` on testfloat.amd64.bin:
#   binary: movss xmm0,[rdi] (4) + movss xmm1,[rdi+N] (5) + add rdi,2N (4) = 13
#   unary:  movss xmm0,[rdi] (4) + add rdi,N (4)                          =  8
_PREAMBLE_BINARY = 13
_PREAMBLE_UNARY = 8

KERNELS: Dict[str, Kernel] = {
    "f32_binary": Kernel(
        ENTRY_F32_BINARY,
        ENTRY_F32_BINARY + _PREAMBLE_BINARY,
        BINARY_PATCHES_SINGLE,
        EXPECT_BINARY_SINGLE,
    ),
    "f32_unary": Kernel(
        ENTRY_F32_UNARY,
        ENTRY_F32_UNARY + _PREAMBLE_UNARY,
        UNARY_PATCHES_SINGLE,
        EXPECT_UNARY_SINGLE,
    ),
    "f64_binary": Kernel(
        ENTRY_F64_BINARY,
        ENTRY_F64_BINARY + _PREAMBLE_BINARY,
        BINARY_PATCHES_DOUBLE,
        EXPECT_BINARY_DOUBLE,
    ),
    "f64_unary": Kernel(
        ENTRY_F64_UNARY,
        ENTRY_F64_UNARY + _PREAMBLE_UNARY,
        UNARY_PATCHES_DOUBLE,
        EXPECT_UNARY_DOUBLE,
    ),
}

# Styx is absent rather than skipped: StyxMachineDef.for_platform raises
# ConfigurationError for X86_64, so there is no variant to list. PANDA is listed
# and then skipped (see _PANDA_NO_SSE) so the variant table records a measured
# defect instead of pretending the engine was never tried.
ENGINES = ("unicorn", "angr", "pcode", "panda")

SPECS: Dict[str, TestFloatSpec] = {
    "amd64": TestFloatSpec(
        platform=PlatformSpec("X86_64", "LITTLE"),
        engines=ENGINES,
        # SysV argument registers, so the kernel reads like the C function it
        # stands in for: rdi/rsi are the two pointers, rdx the count.
        in_register="rdi",
        out_register="rsi",
        count_register="rdx",
        # Nothing to seed: MXCSR already reads round-to-nearest with FTZ and DAZ
        # clear on every backend here. See the module docstring.
        setup={},
        kernels=KERNELS,
    ),
}

# PANDA's x86-64 CPU comes up at the architectural reset state - CR0 reads
# 0x60000010, so PE is clear and it is in real mode, and CR4 reads 0 - and QEMU
# gates every xmm instruction on CR4.OSFXSR. So the first SSE instruction of any
# kernel raises #UD, reported as "Panda exception 6" (EXCP06_ILLOP). Minimal
# case: a four-byte blob holding only `movss xmm0,[rdi]` (F3 0F 10 07); a
# three-byte `stmxcsr [rsi]` (0F AE 1E) does the same.
#
# Seeding CR4 does not rescue it. `cpu.cr4.set(0x600)` (OSFXSR|OSXMMEXCPT) reads
# back as 0x600 afterwards, and a non-SSE blob runs fine with it set, but the
# movss blob still takes exception 6 -- QEMU decides at translation time from
# HF_OSFXSR_MASK in env->hflags, which only cpu_x86_update_cr4() refreshes, and
# PANDA's register write stores the raw field. That is the same class of bug as
# SuperH's FPSCR/`lds` problem, except here the guest has no instruction to fix
# it with: `mov cr4, rax` needs ring 0 and would still be a real-mode CR write.
_PANDA_NO_SSE = (
    "PANDA's x86-64 CPU starts in real mode with CR4=0, so QEMU rejects every "
    "xmm instruction as #UD (exception 6); seeding CR4=0x600 reads back but "
    "does not refresh env->hflags, so it still faults"
)


def function_skip(arch: str, engine: str, func: str) -> Optional[str]:
    """No per-function skips: every enabled cell computes the right answer.

    Kept for symmetry with the other architecture modules, and so that a
    regression can be recorded here without reshaping ``SUPPORT``.
    """
    return None


SUPPORT = ArchSupport(
    specs=SPECS,
    variant_skips={"amd64.panda": _PANDA_NO_SSE},
    function_skip=function_skip,
)

__all__ = ["SUPPORT", "SPECS", "kernel_key"]
