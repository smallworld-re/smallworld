"""ARMv7-A (armhf) guest kernels and encoding tables for the testfloat scenario.

VFP data-processing instructions are one 32-bit A32 word shaped
``cccc 1110 opc1 Vn Vd 101 sz N opc4 M 0 Vm``: the operation lives in bits 23:20
plus bit 6 (``vadd`` 0x3/0, ``vsub`` 0x3/1, ``vmul`` 0x2/0, ``vdiv`` 0x8/0, with
``vsqrt``/``vabs``/``vneg`` in the 0xB "other" group), while bit 8 (``sz``) picks
single or double precision.  Patching only that word therefore swaps the
operation without disturbing the operand registers.

The single- and double-precision tables cannot be shared, and not merely because
of ``sz``: a double names its operand as ``D:Vm`` (bit 22 is the *high* bit) and
a single as ``Vm:M`` (bit 5 is the *low* bit), so the same register pair encodes
differently - ``s1`` is ``M=1, Vm=0`` while ``d1`` is ``D=0, Vm=1``.  Dropping a
single-precision word into the f64 loop decodes cleanly as ``vadd.f32 s0,s0,s1``
and quietly computes single-precision arithmetic on halves of the doubles the
loop loaded, which looks like plausible-but-wrong results rather than a fault.
That is what the ``expect`` strings below guard against.

FPSCR: RMode (bits 23:22) must be 00 for round-to-nearest-even, FZ (bit 24,
flush-to-zero) must be 0 or every subnormal result comes back as zero, DN (bit
25, default NaN) must be 0 to propagate payloads, and the trap-enable bits
(15:8) must be 0 so an inexact or underflow case does not take an exception.
All of that is simply zero.  Unlike SuperH there is no precision bit, so one
value serves all four loops.
"""

from __future__ import annotations

from typing import Dict, Mapping, Optional, Tuple

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

# Round-to-nearest-even, denormals live, no traps enabled: every meaningful
# FPSCR control bit is zero.  Seeded into r3 and installed by the kernel with
# `vmsr fpscr, r3` rather than written straight to the architectural register,
# following the SuperH kernel: a harness-side control-register write is at the
# mercy of whatever shadow state a backend keeps beside it, while `vmsr` is the
# path every backend has to implement correctly to run real code.
FPSCR_INIT = 0x00000000

# op -> (patch bytes in memory order, the disassembly they must produce).
#
# armhf is little-endian, so these are byte-reversed relative to how the ARM ARM
# spells the words (`vadd.f32 s0,s0,s1` is 0xEE300A20, stored 20 0A 30 EE).
# `base.encode_patch` is deliberately not used: it reverses big-endian-spelled
# tables, which would turn every word here back into garbage.
#
# Nothing below was hand-computed.  Each mnemonic was assembled for
# armv7-a/vfpv3-d16, the emitted .text read back, and the bytes and the
# capstone rendering copied out together, so the two halves cannot drift.
_F32_BINARY = {
    "add": ("200a30ee", "vadd.f32 s0, s0, s1"),
    "sub": ("600a30ee", "vsub.f32 s0, s0, s1"),
    "mul": ("200a20ee", "vmul.f32 s0, s0, s1"),
    "div": ("200a80ee", "vdiv.f32 s0, s0, s1"),
}

_F32_UNARY = {
    "sqrt": ("c00ab1ee", "vsqrt.f32 s0, s0"),
    "abs": ("c00ab0ee", "vabs.f32 s0, s0"),
    "neg": ("400ab1ee", "vneg.f32 s0, s0"),
}

_F64_BINARY = {
    "add": ("010b30ee", "vadd.f64 d0, d0, d1"),
    "sub": ("410b30ee", "vsub.f64 d0, d0, d1"),
    "mul": ("010b20ee", "vmul.f64 d0, d0, d1"),
    "div": ("010b80ee", "vdiv.f64 d0, d0, d1"),
}

_F64_UNARY = {
    "sqrt": ("c00bb1ee", "vsqrt.f64 d0, d0"),
    "abs": ("c00bb0ee", "vabs.f64 d0, d0"),
    "neg": ("400bb1ee", "vneg.f64 d0, d0"),
}

# Offsets past each loop's four-instruction prologue (mov / vmsr fpexc / b /
# vmsr fpscr = 16 bytes) and its operand loads: a binary loop issues two vldr
# plus the cursor bump (+12), a unary loop one vldr plus the bump (+8).
# Verified against a disassembly of the built blob.
_BINARY_PATCH = 0x1C
_UNARY_PATCH = 0x18


def _kernel(entry: int, offset: int, table: Mapping[str, Tuple[str, str]]) -> Kernel:
    return Kernel(
        entry,
        entry + offset,
        {op: bytes.fromhex(patch) for op, (patch, _) in table.items()},
        {op: disasm for op, (_, disasm) in table.items()},
    )


KERNELS: Dict[str, Kernel] = {
    "f32_binary": _kernel(ENTRY_F32_BINARY, _BINARY_PATCH, _F32_BINARY),
    "f32_unary": _kernel(ENTRY_F32_UNARY, _UNARY_PATCH, _F32_UNARY),
    "f64_binary": _kernel(ENTRY_F64_BINARY, _BINARY_PATCH, _F64_BINARY),
    "f64_unary": _kernel(ENTRY_F64_UNARY, _UNARY_PATCH, _F64_UNARY),
}

# FPSCR is the only state the harness has to hand over, and it is the same for
# both precisions.  The other piece of control state the kernel needs -
# FPEXC.EN, without which Unicorn rejects every VFP instruction - is built in
# guest code from an immediate instead of being seeded here, because angr is
# VEX-backed and archinfo's ArchARMEL has no `fpexc` register at all, so a
# harness-side write raises UnsupportedRegisterError before the run starts.
_SETUP = {"r3": FPSCR_INIT}

SPECS: Dict[str, TestFloatSpec] = {
    "armhf": TestFloatSpec(
        platform=PlatformSpec("ARM_V7A", "LITTLE"),
        engines=("unicorn", "angr", "pcode", "panda", "styx"),
        in_register="r0",
        out_register="r1",
        count_register="r2",
        setup={"f32": dict(_SETUP), "f64": dict(_SETUP)},
        kernels=KERNELS,
    ),
}


def function_skip(arch: str, engine: str, func: str) -> Optional[str]:
    # Reproduces on armhf exactly as it does on SuperH, which is the point:
    # `vmul.f32`/`vdiv.f32` return +-0 where the reference is the least positive
    # subnormal, so the defect is in Ghidra's float evaluation rather than in any
    # one processor spec. Double precision and add/sub/sqrt are unaffected.
    if func in {"f32_mul", "f32_div"} and engine == "pcode":
        return GHIDRA_FLUSHES_SUBNORMALS
    return None


SUPPORT = ArchSupport(specs=SPECS, function_skip=function_skip)

__all__ = ["SUPPORT", "SPECS", "kernel_key"]
