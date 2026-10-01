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
import typing

from ..platforms import PlatformDef, RegisterAliasDef

# The Ghidra-to-SmallWorld register name mapping lives in
# smallworld.platforms.naming, so that code which must not import the
# instruction model (the build-time ABI generator) can use it. It is
# re-exported here: callers, magrathea among them, import it from here.
from ..platforms.naming import (  # noqa: F401 (re-exported)
    _platform_name,
    canonicalize_register,
    register_alias,
)
from .bsid import BSIDMemoryReferenceOperand
from .instructions import MemoryReferenceOperand, Operand, RegisterOperand

logger = logging.getLogger(__name__)


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
