"""Shared vocabulary for the testfloat scenario's per-architecture kernels.

Everything here is architecture-neutral: the loop offsets every guest source
must honour, the description of one patchable loop, the per-platform spec, and
the skip reasons that belong to a *backend* rather than to any one ISA.
"""

from __future__ import annotations

import dataclasses
from typing import Callable, Mapping, Optional, Tuple

from ..common import PlatformSpec

# Offsets the kernels live at, fixed by `.org` in every architecture's source.
# Four loops plus a shared exit; 0x40 of room each is enough for a load/op/store
# loop on every target we support, and keeping them identical across
# architectures means the harness never has to parse a binary to find an entry.
ENTRY_F32_BINARY = 0x00
ENTRY_F32_UNARY = 0x40
ENTRY_F64_BINARY = 0x80
ENTRY_F64_UNARY = 0xC0
EXIT_OFFSET = 0x100


@dataclasses.dataclass(frozen=True)
class Kernel:
    """Where a loop starts and which instruction byte selects its operation."""

    entry: int
    # offset -> {op: replacement bytes}; the harness writes the bytes for the
    # requested operation before the run.
    patch_offset: int
    patches: Mapping[str, bytes]
    # op -> the disassembly the patch must produce, mnemonic *and* operands, in
    # whatever spelling the target's capstone uses ("fadd fr1, fr0",
    # "addss xmm0, xmm1", "vadd.f32 s0, s0, s1"). Compared after whitespace and
    # case normalisation, so spacing does not matter.
    #
    # Both halves are load-bearing. The mnemonic cannot be derived from the
    # operation name because every architecture spells these differently, and
    # the operands are the half that catches the mistake this guard exists for:
    # a register field belonging to the wrong precision. On SuperH, precision
    # comes from FPSCR.PR rather than the opcode, so the single- and
    # double-precision forms share an encoding shape and a disassembler prints
    # both as `fadd fr...`; only the register numbers distinguish them.
    expect: Mapping[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class TestFloatSpec:
    platform: PlatformSpec
    engines: Tuple[str, ...]
    in_register: str
    out_register: str
    count_register: str
    # Registers to seed before the run, keyed by precision ("f32"/"f64"). Used
    # for whatever control state the kernel needs: on SuperH this hands FPSCR to
    # the kernel in a general register, because the kernel has to install it
    # with `lds` rather than have the harness poke it.
    setup: Mapping[str, Mapping[str, int]]
    kernels: Mapping[str, Kernel]
    compares_flags: bool = False
    stack_base: int = 0x2000
    stack_size: int = 0x4000


@dataclasses.dataclass(frozen=True)
class ArchSupport:
    """One architecture family's contribution to the scenario."""

    specs: Mapping[str, TestFloatSpec]
    # variant name ("sh2a.angr") -> reason; skips the whole variant.
    variant_skips: Mapping[str, str] = dataclasses.field(default_factory=dict)
    # (arch, engine, func) -> reason or None; skips single cells.
    function_skip: Optional[Callable[[str, str, str], Optional[str]]] = None


def op_shape(func: str) -> Tuple[int, int]:
    """(operand width in bytes, operand count) for a TestFloat function name."""
    precision, _, op = func.partition("_")
    width = {"f32": 4, "f64": 8}[precision]
    arity = 1 if op in {"sqrt", "abs", "neg"} else 2
    return width, arity


def kernel_key(func: str) -> str:
    width, arity = op_shape(func)
    return f"f{width * 8}_{'unary' if arity == 1 else 'binary'}"


def normalise_disasm(text: str) -> str:
    """Canonical form for comparing disassembly, so spelling noise cannot fail a
    match that is really correct: lowercase, single-spaced, no space after a
    comma."""
    return " ".join(text.lower().replace(", ", ",").split())


def encode_patch(patch: bytes, big: bool) -> bytes:
    """Order a patch's bytes for the target.

    The tables spell opcodes the way the ISA manual does -- most significant
    byte first -- but a little-endian build stores each instruction word
    byte-swapped, so writing the manual's bytes verbatim into a little-endian
    image decodes as a completely different instruction.

    This applies to fixed-width instruction words. Architectures whose manuals
    already spell opcodes in memory order (x86, where bytes are listed in the
    order they appear) must record them that way and are unaffected, since
    reversing is only requested for big-endian-spelled tables.
    """
    return patch if big else patch[::-1]


# --------------------------------------------------------------------------
# Backend-wide skip reasons
#
# These are properties of an emulator, not of an ISA, so any architecture's
# module may cite them.
# --------------------------------------------------------------------------

# angr's pcode engine implements no floating-point operations at all: every
# OpBehaviorFloat* class in angr/engines/pcode/behavior.py inherits the base
# evaluate_binary/evaluate_unary, which raise AngrError("Not implemented!").
# That is upstream and affects every pcode-backed architecture.
ANGR_NO_FP = "angr's pcode engine implements no floating-point ops (upstream)"

# Ghidra's p-code emulator flushes gradual-underflow results to zero in
# single-precision multiply and divide instead of returning the subnormal.
# Minimal case: 0x00000001 (the least positive subnormal) * 0x3F000001 (0.5)
# yields 0x00000000 where the reference is 0x00000001 with underflow|inexact.
# Every mismatch seen has that shape -- want +-0x00000001, got +-0. It is not a
# SuperH specification bug: Styx executes the *same* sleigh through its own
# p-code engine and passes all five single-precision functions, which places the
# defect in Ghidra's float evaluation. Double precision is unaffected.
GHIDRA_FLUSHES_SUBNORMALS = (
    "Ghidra's p-code emulator flushes subnormal f32 mul/div results to zero "
    "(0x00000001 * 0.5 -> 0, want 0x00000001); Styx on the same sleigh passes"
)
