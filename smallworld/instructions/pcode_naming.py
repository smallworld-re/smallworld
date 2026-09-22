"""Mapping Ghidra register names into SmallWorld's register namespace.

The pcode use/def analysis (:mod:`.pcode_use_def`) is deliberately
unaware of platform definitions: it takes a SLEIGH language id and
reports operands using *Ghidra's* register naming, which is what the
validation corpus under ``tests/pcode_use_def/`` checks it against.

This module is the other side of that boundary -- the adapter that turns
one of those results into operands a consumer can concretize against an
emulator, which means names that exist in
:attr:`PlatformDef.registers`. Ghidra's naming mostly matches SmallWorld's
but differs in a few places (flag bits vs. a flags register, vector-lane
pseudo-registers, hi/lo accumulator naming); names with no platform
equivalent even after aliasing (e.g. AArch64 condition flags today) are
dropped.

It lives apart from :mod:`.pcode_use_def` because none of this needs
pyghidra or a Ghidra install -- it is plain Python over a platform
definition -- and apart from :mod:`.instructions` because it is one
backend's naming quirks rather than part of the instruction model.
"""

import logging
import re
import typing

from ..platforms import Architecture, PlatformDef, RegisterAliasDef
from .bsid import BSIDMemoryReferenceOperand
from .instructions import MemoryReferenceOperand, Operand, RegisterOperand

logger = logging.getLogger(__name__)

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


def canonicalize_operand(
    operand: Operand, platdef: PlatformDef
) -> typing.Optional[Operand]:
    """Map one operand from the pcode analysis into this platform's
    register namespace so consumers can concretize it against an
    emulator. Returns None for operands naming state the platform
    definition doesn't model."""
    if isinstance(operand, RegisterOperand):
        name = _platform_name(operand.name, platdef)
        if name is None:
            logger.debug(
                f"dropping pcode operand {operand.name!r}: "
                f"no such register on {type(platdef).__name__}"
            )
            return None
        if name != operand.name:
            return RegisterOperand(name)
        return operand

    if isinstance(operand, MemoryReferenceOperand):
        # base and index are register names too. Passed through raw, a
        # Ghidra-only name (x86-64 fs_offset, MIPS64's <reg>_lo) reached an
        # operand whose .address() raises when a consumer resolves it.
        renamed = {}
        for attr in ("base", "index"):
            name = getattr(operand, attr, None)
            if name is None:
                continue
            mapped = _platform_name(name, platdef)
            if mapped is None:
                # No resolvable base or index means no address, so drop the
                # whole reference. Debug, like the register case: TLS
                # accesses would make a warning here constant noise.
                logger.debug(
                    f"dropping pcode memory operand {operand!r}: {attr} "
                    f"{name!r} is not a register on {type(platdef).__name__}"
                )
                return None
            if mapped != name:
                renamed[attr] = mapped

        # p-code has no segment concept: SLEIGH flattens `fs:[0x28]` into an
        # add against Ghidra's FS_OFFSET, which arrives here as the base
        # register fsbase. Capstone reports the same access as segment="fs"
        # with no base. Both are resolvable, but consumers classify a
        # segment-relative access by the `segment` field, so a backend that
        # never sets it makes the access unrecognizable. Fold the segment base
        # back into `segment` so p-code names it the way Capstone does;
        # address() adds it back.
        #
        # `segment` and the resolved address agree exactly after this. The
        # base/index SPLIT still cannot, and no fold can fix that: Capstone
        # reports the encoding, where `fs:[rbx+8]` puts rbx in ModRM base and
        # `gs:[rdx*1+0x13]` puts rdx in the SIB index with no base, while
        # SLEIGH flattens both to the same sum. The promotion below picks the
        # ModRM reading because it is far the commoner encoding; the scaled
        # SIB form is where the two still disagree.
        was = getattr(operand, "segment", None)
        segment = was
        base = renamed.get("base", getattr(operand, "base", None))
        index = renamed.get("index", getattr(operand, "index", None))
        scale = getattr(operand, "scale", 1)
        if segment is None and platdef.segment_base_registers:
            for seg, base_reg in platdef.segment_base_registers.items():
                # Which slot the flattened base landed in is just the order
                # _expr_to_bsid met the terms (base first, then index), not a
                # guarantee -- so check both. `index` only at scale 1: a
                # scaled segment base is not a segment reference.
                if base == base_reg:
                    segment, base = seg, None
                elif index == base_reg and scale == 1:
                    segment, index = seg, None
                else:
                    continue
                if base is None and index is not None and scale == 1:
                    # The segment base displaced the real base into `index`;
                    # put it back, so the operand has the base/index split
                    # Capstone reports rather than one that only differs
                    # because SLEIGH spelled the address as a sum.
                    base, index = index, None
                break

        if renamed or segment != was:
            # type(operand), not the base class: a subclass carries both
            # behaviour (x86's rip fixup) and identity (__repr__ embeds the
            # class name, and equality keys on the repr).
            cls = (
                type(operand)
                if isinstance(operand, BSIDMemoryReferenceOperand)
                else BSIDMemoryReferenceOperand
            )
            return cls(
                segment=segment,
                base=base,
                index=index,
                scale=scale,
                offset=getattr(operand, "offset", 0),
                size=operand.size,
            )
    return operand


def collapse_widened_defs(
    operands: typing.Set[Operand], platdef: PlatformDef
) -> typing.Set[Operand]:
    """Drop a register def that is redundant given a def of one of its
    own sub-registers.

    Ghidra models a 32-bit x86-64 write as zero-extending, so
    `mov ecx, eax` reports defs of both ECX and RCX. Both are true, but
    consumers key on the architectural destination, so keep the narrower
    name the instruction actually names and drop the widened parent.

    Applied to defs only: for a def the parent is the strictly larger
    effect and is safe to summarize by its part, whereas dropping a
    parent *read* would understate what was consumed.

    KNOWN GAP: that premise holds when the parent write was CAUSED by the
    child's (x86 zero-extension) and not when the two are independent. AVX
    writes ymm0's upper half through its own varnodes, so `vaddps ymm0,
    ymm1, ymm2` reports {xmm0} and a consumer concludes bytes 16..31 are
    untouched. Legacy SSE, which really does preserve the upper half, is
    reported correctly. Both look identical here -- a {child, parent} pair
    -- so telling them apart needs the architectural destination, which
    Capstone names but this layer is not given.
    """
    names = {op.name for op in operands if isinstance(op, RegisterOperand)}
    redundant = set()
    for name in names:
        reg = platdef.registers.get(name)
        if isinstance(reg, RegisterAliasDef) and reg.parent in names:
            redundant.add(reg.parent)
    if not redundant:
        return operands
    return {
        op
        for op in operands
        if not (isinstance(op, RegisterOperand) and op.name in redundant)
    }
