"""Mapping Ghidra register names onto a platform's registers.

:func:`canonicalize_register` turns a Ghidra (SLEIGH) register name into the
name a :class:`~smallworld.platforms.defs.PlatformDef` uses, or ``None`` when
the platform models no such register. It is plain Python over a platform
definition: it imports only :mod:`.platforms` and :mod:`.defs`, so the
build-time ABI generator (``tools/abi``) can load it without importing the
rest of smallworld. :mod:`smallworld.instructions.pcode_naming` re-exports it.
"""

import re
import typing

from .defs import PlatformDef
from .platforms import Architecture

_X86_FLAG_BITS = frozenset(
    ("cf", "pf", "af", "zf", "sf", "of", "df", "tf", "if", "ac", "id")
)
# Ghidra models SSE/AVX lanes as pseudo-registers: xmm0_qa, xmm0_da, ...
_X86_VECTOR_LANE_RE = re.compile(r"([xyz]mm\d+)_\w+")
_AARCH64_FLAG_BITS = frozenset(("ng", "zr", "cy", "ov", "nzcv"))
_AARCH64_ZREG_RE = re.compile(r"z(\d+)")
# Ghidra's MIPS64 model names the 32-bit view of a 64-bit GPR <reg>_lo and
# the upper half <reg>_hi. A 32-bit op (addu, sll, ...) reads and writes the
# _lo view and sign-extends into the whole register, so for use/def purposes
# both views are the architectural register -- the same reduction x86 eax ->
# rax and AArch64 w3 -> x3 get.
_MIPS64_SUBREG_RE = re.compile(r"(.+)_(?:lo|hi)")


def register_alias(name: str, arch: Architecture) -> str:
    """The SmallWorld spelling of a Ghidra register name, or the name
    unchanged when the two already agree."""
    if arch == Architecture.X86_64:
        if name in _X86_FLAG_BITS:
            return "rflags"
        m = _X86_VECTOR_LANE_RE.fullmatch(name)
        if m:
            return m.group(1)
    elif arch == Architecture.X86_32:
        if name in _X86_FLAG_BITS:
            return "eflags"
        m = _X86_VECTOR_LANE_RE.fullmatch(name)
        if m:
            return m.group(1)
    elif arch == Architecture.AARCH64:
        # no PlatformDef register models the flags today; alias to nzcv
        # so they all drop as one name (and start flowing through the
        # moment the platform definition gains it)
        if name in _AARCH64_FLAG_BITS:
            return "nzcv"
        # zN is Ghidra's full vector register; qN is the widest lane
        # SmallWorld models
        m = _AARCH64_ZREG_RE.fullmatch(name)
        if m:
            return f"q{m.group(1)}"
    elif arch in (Architecture.POWERPC32, Architecture.POWERPC64):
        # Both share PowerPCPlatformDef's register set and both carry a
        # ghidra_language_id, so keying on POWERPC32 alone silently dropped
        # every one of these operands on 64-bit PowerPC.
        if name == "xer" or name.startswith("xer_"):
            # The platform models XER (which is SPR 1) under its SPR name;
            # there is no plain "xer" RegisterDef, so aliasing to that
            # silently dropped every carry and overflow edge. Ghidra spells
            # the bits xer_ca/xer_ov/... and the whole register bare "xer"
            # (mfxer/mtxer), so both have to map.
            return "spr_xer"
        if name.startswith("fp_"):
            return "fpscr"
    elif arch == Architecture.MIPS32:
        if name == "hi":
            return "hi0"
        if name == "lo":
            return "lo0"
    elif arch == Architecture.MIPS64:
        m = _MIPS64_SUBREG_RE.fullmatch(name)
        if m:
            return m.group(1)
    return name


def _platform_name(ghidra_name: str, platdef: PlatformDef) -> typing.Optional[str]:
    """This platform's name for a Ghidra register, or None if it models no
    such register."""
    name = register_alias(ghidra_name, platdef.architecture)
    # A platform may also rename registers wholesale, where the two
    # namespaces use the same word for different physical registers --
    # MIPS64, where Ghidra's O32 t0 is N64's a4. Applied after
    # register_alias so it sees the reduced name (t0_lo -> t0 -> a4).
    name = platdef.ghidra_register_aliases.get(name, name)
    if name not in platdef.registers:
        return None
    return name


def canonicalize_register(
    ghidra_name: str, platdef: PlatformDef
) -> typing.Optional[str]:
    """This platform's name for a Ghidra register, or None if it models no
    such register. Public counterpart of the mapping `canonicalize_operand`
    applies, for callers holding a bare register name rather than an
    Operand."""
    return _platform_name(ghidra_name, platdef)


__all__ = ["canonicalize_register", "register_alias"]
