"""ARMv7E-M (armv7em) guest kernels and encoding tables for the testfloat scenario.

The FPU is FPv4-SP, as on the Cortex-M4F. Its data-processing instructions
encode exactly as the A-profile VFP ones (see ``armv7a``), but in Thumb they
are two halfwords, stored high halfword first: `vadd.f32 s0,s0,s1` is
0xEE300A20, stored 30 EE 20 0A.

FPv4-SP is single precision only. Its register file still has d0-d15, for
moves, loads and stores, but no double-precision arithmetic, so the f64
functions are skipped rather than run in software.

FPSCR: as on armv7a, every meaningful control bit is zero (round to nearest
even, no flush to zero, no default NaN), and the kernel installs it from r3.
"""

from __future__ import annotations

from typing import Dict, Mapping, Optional, Tuple

from ..common import PlatformSpec
from .base import (
    ANGR_NO_SCALAR_SQRT,
    ENTRY_F32_BINARY,
    ENTRY_F32_UNARY,
    GHIDRA_FLUSHES_SUBNORMALS,
    ArchSupport,
    Kernel,
    TestFloatSpec,
)

FPSCR_INIT = 0x00000000

# op -> (patch bytes in memory order, the disassembly they must produce).
# Assembled for cortex-m4 and read back, bytes and capstone rendering together.
_F32_BINARY = {
    "add": ("30ee200a", "vadd.f32 s0, s0, s1"),
    "sub": ("30ee600a", "vsub.f32 s0, s0, s1"),
    "mul": ("20ee200a", "vmul.f32 s0, s0, s1"),
    "div": ("80ee200a", "vdiv.f32 s0, s0, s1"),
}

_F32_UNARY = {
    "sqrt": ("b1eec00a", "vsqrt.f32 s0, s0"),
    "abs": ("b0eec00a", "vabs.f32 s0, s0"),
    "neg": ("b1ee400a", "vneg.f32 s0, s0"),
}

# Offsets past each loop's `vmsr fpscr` (4 bytes) and its operand loads: a
# binary loop issues two vldr plus a 2-byte cursor bump (+10), a unary loop one
# vldr plus the bump (+6). Verified against a disassembly of the built blob.
_BINARY_PATCH = 0x0E
_UNARY_PATCH = 0x0A


def _kernel(entry: int, offset: int, table: Mapping[str, Tuple[str, str]]) -> Kernel:
    return Kernel(
        entry,
        entry + offset,
        {op: bytes.fromhex(patch) for op, (patch, _) in table.items()},
        {op: disasm for op, (_, disasm) in table.items()},
    )


# No f64 kernels: FPv4-SP can't run them, and `function_skip` says so.
KERNELS: Dict[str, Kernel] = {
    "f32_binary": _kernel(ENTRY_F32_BINARY, _BINARY_PATCH, _F32_BINARY),
    "f32_unary": _kernel(ENTRY_F32_UNARY, _UNARY_PATCH, _F32_UNARY),
}

SPECS: Dict[str, TestFloatSpec] = {
    "armv7em": TestFloatSpec(
        platform=PlatformSpec("ARM_V7EM", "LITTLE"),
        engines=("unicorn", "angr", "pcode", "panda", "styx"),
        in_register="r0",
        out_register="r1",
        count_register="r2",
        setup={"f32": {"r3": FPSCR_INIT}},
        kernels=KERNELS,
    ),
}

_NO_DOUBLE = "FPv4-SP is single precision only; it has no f64 arithmetic"


def function_skip(arch: str, engine: str, func: str) -> Optional[str]:
    if func.startswith("f64_"):
        return _NO_DOUBLE
    # Both measured here, and both as on armv7a: Ghidra returns +-0 where the
    # reference is the least positive subnormal, and angr has no calculate
    # function for Iop_SqrtF32.
    if func in {"f32_mul", "f32_div"} and engine == "pcode":
        return GHIDRA_FLUSHES_SUBNORMALS
    if func == "f32_sqrt" and engine == "angr":
        return ANGR_NO_SCALAR_SQRT
    return None


# Measured: writing the output buffer fails with
# UnmappedMemory(UnmappedStart(0x200000)) before the first instruction runs.
_STYX_NO_BUFFERS = (
    "Styx's Kinetis21 target has no memory at testfloat's buffer addresses"
)

SUPPORT = ArchSupport(
    specs=SPECS,
    variant_skips={"armv7em.styx": _STYX_NO_BUFFERS},
    function_skip=function_skip,
)

__all__ = ["SUPPORT", "SPECS"]
