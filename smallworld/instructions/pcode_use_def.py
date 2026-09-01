"""
Compute use/def sets for machine instructions using Ghidra's raw pcode,
via pypcode.

pypcode wraps SLEIGH, the C++ half of Ghidra: it turns bytes into pcode ops
and knows the language's register namespace, which is all this analysis
needs. Not pyghidra, which drives Ghidra's Java half and so puts a JVM in the
caller's process -- a forked child inherits the JVM's mutexes without its
threads and deadlocks forever, and the first call costs seconds. Same engine
underneath, so the same p-code, delay-slot expansion included.

For each machine instruction we ask SLEIGH for its pcode translation and
then walk the pcode ops:

    * Each pcode op has 0..N input varnodes (reads) and 0..1 output
      varnode (write).
    * A varnode can live in one of several address spaces:
        - register : a CPU register
        - ram      : a fixed memory location (rare for raw pcode, but
                     possible — e.g. absolute loads/stores)
        - const    : an immediate; not a storage location, ignored.
        - unique   : a pcode-internal temporary that exists only inside
                     the instruction; not visible to the rest of the
                     program, so it is ignored for instruction-level
                     use/def.
        - stack    : function-local stack offsets (only appears after
                     higher-level analysis; raw pcode usually keeps
                     these as register+offset memory ops).

Instruction-level use/def, in classic gen/kill form:

    use[i] = { locations read by i before being (re)defined by i }
    def[i] = { locations written by i }

Because a single machine instruction can produce several pcode ops, an
input read after an earlier write within the same instruction would not
be a true "use" of that instruction (the read sees the value the
instruction itself produced). We mirror that by tracking what has
already been written in the current instruction and excluding it from
the use set.

The public entry point is analyze(byte_data, ghidra_language,
base_address), which returns the use/def of the single instruction at
base_address. It is used by smallworld.instructions.Instruction.reads /
.writes.
"""

import dataclasses
import functools
import logging
import threading
import typing
from enum import Enum, auto

import pypcode

from smallworld.instructions import Operand, RegisterOperand
from smallworld.instructions.bsid import BSIDMemoryReferenceOperand

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# SLEIGH contexts                                                             #
# --------------------------------------------------------------------------- #
#
# One Context per language, kept for the life of the process: building one
# costs tens of milliseconds, translating against it is sub-millisecond.
# Translation is stateless, so unlike the pyghidra implementation there is no
# program to repopulate, nothing to evict on error and nothing to tear down.
_contexts: dict = {}


def _get_context(language_id: str) -> "pypcode.Context":
    """The cached Context for `language_id`, building it on first use.

    Raises ValueError for a language SLEIGH does not know:
    `Instruction._pcode_result` classifies that as a configuration problem.
    """
    ctx = _contexts.get(language_id)
    if ctx is None:
        try:
            ctx = pypcode.Context(language_id)
        except Exception as e:
            raise ValueError(f"unknown SLEIGH language {language_id!r}: {e}") from e
        _contexts[language_id] = ctx
    return ctx


# Space names SLEIGH uses. `ram` is the only address-type space this
# analysis models; a language with several (Harvard/DSP CODE/DATA/SFR) is
# rejected per-varnode below rather than silently treated as ram.
_CONST_SPACE = "const"
_UNIQUE_SPACE = "unique"
_REGISTER_SPACE = "register"
_RAM_SPACE = "ram"


def _is_const(vn) -> bool:
    return vn.space.name == _CONST_SPACE


def _is_unique(vn) -> bool:
    return vn.space.name == _UNIQUE_SPACE


def _is_register(vn) -> bool:
    return vn.space.name == _REGISTER_SPACE


def _is_addr(vn) -> bool:
    """True for a varnode naming a concrete memory address.

    Like Ghidra's `Varnode.isAddress()`, true for every address-type space
    rather than only the one named "ram"; `_varnode_operand` narrows it.
    """
    return vn.space.name not in (_CONST_SPACE, _UNIQUE_SPACE, _REGISTER_SPACE)


@dataclasses.dataclass(frozen=True)
class _RegSlot:
    """Value-identity key for a register varnode, for the symbolic state.

    pypcode's Varnode hashes by OBJECT IDENTITY where Ghidra's compared by
    value. The symbolic state relies on value equality to follow a register
    an instruction assigns to itself part-way through (ARM `ldm`'s
    `mult_addr`); keyed by varnode, the second and later cells of a
    load/store-multiple went unreported.

    Deliberately not a tuple: unique varnodes are keyed in the same dict by a
    plain (offset, size) tuple, which a 2-field NamedTuple would compare and
    hash equal to, silently merging a register with a same-numbered unique.
    """

    offset: int
    size: int


def _reg_slot(vn) -> _RegSlot:
    return _RegSlot(int(vn.offset), int(vn.size))


def _vn_str(vn) -> str:
    """Varnode rendering for error messages: space, offset and size."""
    return f"({vn.space.name}, {vn.offset:#x}, {vn.size})"


# Per-language (offset, size, name) intervals, for finding the smallest
# register containing a varnode that no register names exactly (AArch64's
# upper-lane writes at z0+8). Keyed by id(): `_contexts` keeps Contexts alive.
_register_intervals: dict = {}


def _register_intervals_for(ctx):
    intervals = _register_intervals.get(id(ctx))
    if intervals is None:
        intervals = [
            (int(vn.offset), max(1, int(vn.size)), name)
            for name, vn in ctx.registers.items()
            if vn.space.name == _REGISTER_SPACE
        ]
        _register_intervals[id(ctx)] = intervals
    return intervals


def _containing_register(ctx, vn):
    """Name of the smallest named register wholly containing `vn`, or None."""
    off = int(vn.offset)
    size = int(vn.size)
    best = None
    for koff, ksize, name in _register_intervals_for(ctx):
        if koff <= off and off + size <= koff + ksize:
            if best is None or ksize < best[0]:
                best = (ksize, name)
    return best[1] if best else None


def _reg_name(ctx, vn):
    """Name (lowercase) of the register a register-space varnode denotes.

    SLEIGH names the register at exactly this address and size ("eax" vs
    "rax") when there is one; otherwise fall back to the smallest named
    register containing the varnode's byte range.
    """
    name = vn.getRegisterName()
    if not name:
        name = _containing_register(ctx, vn)
    if not name:
        raise UseDefError(f"no register found for varnode {_vn_str(vn)}")
    return name.lower()


def _varnode_operand(ctx, vn):

    # returning None seems to signal that this is neither a Reg nor memory.
    if vn is None:
        return None
    if _is_const(vn):
        return None
    if _is_unique(vn):
        return None

    if _is_register(vn):
        return RegisterOperand(_reg_name(ctx, vn))

    # Anything left has to be a concrete address. UseDefError rather than
    # assert: `python -O` strips asserts, which would silently report some
    # other memory space as ram.
    if not _is_addr(vn):
        raise UseDefError(f"varnode {_vn_str(vn)} is in no space this analysis models")
    space = vn.space.name
    if space != _RAM_SPACE:
        # Harvard/DSP languages define several address-type spaces
        # (CODE/DATA/SFR/...); only ram is modeled here.
        raise UseDefError(f"memory varnode in address space {space!r}")
    return BSIDMemoryReferenceOperand(
        segment=None,
        base=None,
        index=None,
        scale=1,
        offset=int(vn.offset) & ((1 << 64) - 1),
        size=int(vn.size),
    )


def _unique_key(vn):
    """Hashable key for a unique-space varnode."""
    return (int(vn.offset), int(vn.size))


def _same_register(a, b):
    """True if two varnodes denote the exact same register (same
    register-space offset and size)."""
    return (
        _is_register(a)
        and _is_register(b)
        and a.offset == b.offset
        and a.size == b.size
    )


# Registers (lowercase) that exist only as Ghidra modeling devices, not
# architectural state, and must never appear in use/def sets:
#   r2save        — PPC bl/blr TOC-pointer save slot
#   tea           — PPC temporary effective address (lmw/stmw)
#   isamodeswitch — MIPS16e/micromips mode bit written by indirect jumps
#   tmp*          — SLEIGH scratch, see _GHIDRA_SCRATCH_PREFIXES below
#   shift_carry   — ARM/AArch64 barrel-shifter carry scratch
#   mult_addr     — ARM running-address accumulator for ldm/stm/push/pop
_GHIDRA_INTERNAL_REGS = {
    "r2save",
    "tea",
    "isamodeswitch",
    "shift_carry",
    "mult_addr",
}

# SLEIGH scratch registers share a prefix, and a fixed name list misses them:
# AArch64 alone has tmpd1-6, tmps1-6, tmpq1-6, tmpz1-6 and tmp_ld*/tmp_st* on
# top of the four flag temporaries once listed, so `zip1` reported uses of
# scratch a previous instruction left behind. No supported architecture has a
# real register named tmp*.
_GHIDRA_SCRATCH_PREFIXES = ("tmp",)


def _is_ghidra_internal(name: str) -> bool:
    """True for a register that exists only as a Ghidra modeling device."""
    return name in _GHIDRA_INTERNAL_REGS or name.startswith(_GHIDRA_SCRATCH_PREFIXES)


# Internal registers for which a COPY is pure noise on BOTH sides and the
# whole op should be dropped, versus internals that merely relay a real
# register (an address accumulator seeded from a base register), where
# the op must still be processed so the real operand is captured.
#
# r2save is the PPC bl/blr TOC-pointer save/restore shuffle: it copies
# r2 <-> r2save, and neither is a genuine data effect, so erase the op.
# By contrast ARM ldm/stm's mult_addr and PPC lmw/stmw's tea are seeded
# by 'COPY base -> accumulator' / written back by 'COPY accumulator ->
# base'; dropping those ops would lose the base register's read and
# writeback, so they are handled by per-operand filtering instead.
_GHIDRA_COPY_ERASE_REGS = {"r2save"}


# --------------------------------------------------------------------------- #
# Symbolic-expression machinery for STORE/LOAD addresses
# --------------------------------------------------------------------------- #
#
# Within a single machine instruction we trace data flow through pcode
# 'unique' temporaries so that when we hit a STORE/LOAD we can render
# the memory address symbolically — e.g. for PPC's
#
#     stwu r1, -0x30(r1)
#
# we want to emit a def of  ram[(r1 + -0x30):4]  rather than just
# noting "memory got written somewhere". The trick is that the address
# was computed in a unique by an earlier INT_ADD; we store that
# unique's expression as a string keyed by its (offset, size) and
# substitute it back when the STORE consumes it.


class _PCODE_OP(Enum):
    COPY = auto()
    LOAD = auto()
    STORE = auto()
    BRANCH = auto()
    CBRANCH = auto()
    BRANCHIND = auto()
    CALL = auto()
    CALLIND = auto()
    RETURN = auto()
    PIECE = auto()
    SUBPIECE = auto()
    INT_EQUAL = auto()
    INT_NOTEQUAL = auto()
    INT_LESS = auto()
    INT_SLESS = auto()
    INT_LESSEQUAL = auto()
    INT_SLESSEQUAL = auto()
    INT_ZEXT = auto()
    INT_SEXT = auto()
    INT_ADD = auto()
    INT_SUB = auto()
    INT_CARRY = auto()
    INT_SCARRY = auto()
    INT_SBORROW = auto()
    INT_2COMP = auto()
    INT_NEGATE = auto()
    INT_XOR = auto()
    INT_AND = auto()
    INT_OR = auto()
    INT_LEFT = auto()
    INT_RIGHT = auto()
    INT_SRIGHT = auto()
    INT_MULT = auto()
    INT_DIV = auto()
    INT_REM = auto()
    INT_SDIV = auto()
    INT_SREM = auto()
    BOOL_NEGATE = auto()
    BOOL_XOR = auto()
    BOOL_AND = auto()
    BOOL_OR = auto()
    FLOAT_EQUAL = auto()
    FLOAT_NOTEQUAL = auto()
    FLOAT_LESS = auto()
    FLOAT_LESSEQUAL = auto()
    FLOAT_ADD = auto()
    FLOAT_SUB = auto()
    FLOAT_MULT = auto()
    FLOAT_DIV = auto()
    FLOAT_NEG = auto()
    FLOAT_ABS = auto()
    FLOAT_SQRT = auto()
    # SLEIGH prefixes these FLOAT_ where Ghidra's Java PcodeOp spelled them
    # bare. Lookup is BY NAME, so the spelling is load-bearing: the bare
    # names matched nothing and every float conversion took the UNKNOWN path.
    FLOAT_CEIL = auto()
    FLOAT_FLOOR = auto()
    FLOAT_ROUND = auto()
    FLOAT_NAN = auto()
    FLOAT_INT2FLOAT = auto()
    FLOAT_FLOAT2FLOAT = auto()
    FLOAT_TRUNC = auto()
    # ops below occur in raw pcode but need no special handling in the
    # use/def walk; they are listed so mnemonic lookup doesn't KeyError.
    # POPCOUNT appears in x86 parity-flag computation, LZCOUNT in
    # clz-style instructions, CALLOTHER wraps black-box user ops (locked
    # RMW, syscalls, hints, ...).
    CALLOTHER = auto()
    POPCOUNT = auto()
    LZCOUNT = auto()
    MULTIEQUAL = auto()
    INDIRECT = auto()
    CAST = auto()
    PTRADD = auto()
    PTRSUB = auto()
    SEGMENTOP = auto()
    CPOOLREF = auto()
    NEW = auto()
    INSERT = auto()
    EXTRACT = auto()
    # SPULL/ZPULL appear in stack-machine languages. INVALID_OP and
    # UNIMPLEMENTED were Ghidra's "no semantics" markers; SLEIGH raises
    # UnimplError instead, which _analyze_locked turns into the same
    # UseDefError. Kept so either shape is handled.
    SPULL = auto()
    ZPULL = auto()
    INVALID_OP = auto()
    UNIMPLEMENTED = auto()
    # Not a Ghidra mnemonic: what _mnemonic_of returns for an op this
    # module has never heard of. Deliberately matches no branch in the
    # walk, so such an op takes the generic path.
    UNKNOWN = auto()


_warned_mnemonics: typing.Set[str] = set()


def _mnemonic_of(op) -> "_PCODE_OP":
    """The `_PCODE_OP` for a pcode op, or UNKNOWN if it names one this
    module does not model.

    `_PCODE_OP` is an allowlist keyed by Ghidra's own mnemonic strings, so
    it is only ever as complete as the Ghidra it was written against. A
    bare `_PCODE_OP[...]` made every gap a KeyError escaping `analyze()`
    into the colorizer and trace analyses -- and three gaps shipped
    (CEIL/FLOOR/ROUND, from spelling them FLOAT_*), which is what
    `cvtsd2si`, `frndint` and MIPS `ceil.w.s` hit. Falling back to UNKNOWN
    sends the op down the generic path -- inputs are uses, the output is a
    def -- the conservative reading of an op whose special meaning we do
    not know.
    """
    name = op.opcode.name
    try:
        return _PCODE_OP[name]
    except KeyError:
        if name not in _warned_mnemonics:
            _warned_mnemonics.add(name)
            logger.warning(
                f"unmodelled pcode op {name!r}; treating its inputs as uses "
                f"and its output as a def"
            )
        return _PCODE_OP.UNKNOWN


# Binary pcode ops whose result is a constant when both inputs are the
# same value: x-x=0, x^x=0, signed borrow of x-x=0, and the reflexive
# comparisons (x==x, x<x, x<=x). For these, an operand read of a
# register against itself carries no information, so it is not a real
# use. INT_ADD/INT_MULT (depend on the value), INT_AND/INT_OR (return
# the value), and INT_CARRY/INT_SCARRY (a+a overflow depends on a) are
# intentionally absent.
_CONST_ON_IDENTICAL_INPUTS = frozenset(
    {
        _PCODE_OP.INT_XOR,
        _PCODE_OP.INT_SUB,
        _PCODE_OP.INT_SBORROW,
        _PCODE_OP.INT_EQUAL,
        _PCODE_OP.INT_NOTEQUAL,
        _PCODE_OP.INT_LESS,
        _PCODE_OP.INT_SLESS,
        _PCODE_OP.INT_LESSEQUAL,
        _PCODE_OP.INT_SLESSEQUAL,
        _PCODE_OP.BOOL_XOR,
    }
)


def _space_name(ctx, space_id_vn):
    """STORE/LOAD encode the destination address space in input[0], a
    'constant' varnode.

    Its offset is SLEIGH's own handle for the space, not a portable id, so
    ask the varnode to resolve it rather than decoding the constant.
    """
    space = space_id_vn.getSpaceFromConst()
    return space.name if space is not None else f"space{int(space_id_vn.offset):#x}"


class InstructionUseDef(typing.NamedTuple):
    """Use/def of a single decoded instruction; the result of `analyze`.

    `size` is how many bytes Ghidra consumed for this instruction, which
    lets a caller confirm the buffer held exactly the instruction it
    meant to analyze.
    """

    disassembly: str
    size: int
    uses: typing.Tuple[Operand, ...]
    defs: typing.Tuple[Operand, ...]
    #: Registers whose *value* is the destination of an indirect transfer
    #: (BRANCHIND/CALLIND/RETURN) -- MIPS `jr $t9`, x86 `jmp rax`. Reported
    #: separately because "this register holds a code pointer" is structure
    #: the flat use set cannot express, and a consumer that models the
    #: implicit dereference needs to know WHICH register is dereferenced
    #: rather than guessing from the whole read set.
    indirect_targets: typing.Tuple[str, ...] = ()


class UseDefError(Exception):
    """A pcode construct the use/def analysis cannot yet interpret."""

    pass


# Resolve one input varnode to an expression over quantities that were
# live at instruction entry. Returns:
# * the varnode itself for a const, ram address, or register that has
#   not yet been written by this instruction
# * the recorded expression for a unique, or for a register that HAS
#   been written earlier in this instruction. Values stored in sstate
#   were resolved when they were stored, so they can be returned as-is;
#   they never need re-resolution.
def _resolve_input(inp, sstate):
    if _is_unique(inp):
        ik = _unique_key(inp)
        if ik in sstate:
            return sstate[ik]
        # Ghidra sometimes reads a sub-range of a wider temporary
        # directly by offset+size instead of emitting SUBPIECE (e.g.
        # MIPS mult reads the low word of the 64-bit product as
        # (unique, base+4, 4)). Truncation doesn't change which
        # locations are used, so resolve to the containing expression.
        off, size = ik
        for k, val in sstate.items():
            if isinstance(k, _RegSlot):
                continue
            koff, ksize = k
            if koff <= off and off + size <= koff + ksize:
                return val
        raise UseDefError(f"unique read before write: {inp}")
    if _is_register(inp):
        slot = _reg_slot(inp)
        if slot in sstate:
            # Register assigned earlier in this instruction: a read now
            # sees the value this instruction computed, not the
            # instruction input.
            return sstate[slot]
        # same sub-range logic as uniques, for partial register reads
        # of a register this instruction already wrote
        off = int(inp.offset)
        size = int(inp.size)
        for k, val in sstate.items():
            if not isinstance(k, _RegSlot):
                continue
            koff = int(k.offset)
            ksize = int(k.size)
            if koff <= off and off + size <= koff + ksize:
                return val
        return inp
    # const, ram address, or register still holding its entry value
    return inp


def _update_symstate(op, sstate):
    # resolve all inputs (args) to this op in terms of
    # inputs-to-the-instruction, and then record
    # mapping from out to that resolution
    ris = [_resolve_input(inp, sstate) for inp in op.inputs]
    # special case! There's no need for an s-expr. This is basically
    # just an assignment
    mnemonic = _mnemonic_of(op)
    if mnemonic == _PCODE_OP.COPY:
        assert (len(ris)) == 1
        val = ris[0]
    else:
        val = (mnemonic, ris)
    outp = op.output
    if outp is None:
        # no output to track (e.g. STORE, branches)
        return
    if _is_unique(outp):
        sstate[_unique_key(outp)] = val
    elif _is_register(outp):
        sstate[_reg_slot(outp)] = val
    # else: output is a ram address (absolute store via COPY); nothing
    # downstream reads it back through sstate, so don't track it


def _const_value(vn):
    """Value of a constant varnode, interpreted as signed at its size.

    A varnode's offset is an unsigned value at its own width, so mask to
    that width first, then sign-interpret it.
    """
    size = int(vn.size)
    if size < 1 or size > 8:
        return int(vn.offset)
    width = size * 8
    val = int(vn.offset) & ((1 << width) - 1)
    if val & (1 << (width - 1)):
        val -= 1 << width
    return val


def _unwrap_ext(expr):
    """Strip INT_ZEXT/INT_SEXT wrappers; width changes in address
    arithmetic don't alter the symbolic base+scale*index+offset form."""
    while isinstance(expr, tuple) and expr[0] in (
        _PCODE_OP.INT_ZEXT,
        _PCODE_OP.INT_SEXT,
    ):
        expr = expr[1][0]
    return expr


def _flatten_sum(expr, sign, terms, size):
    """Flatten an address expression into a list of (sign, term) where
    each term is a varnode or a multiplicative sub-expression.

    `size` is the access width in bytes, which bounds the one
    approximation made here -- see the INT_AND branch.
    """
    expr = _unwrap_ext(expr)
    if isinstance(expr, tuple):
        mnem, args = expr
        if mnem == _PCODE_OP.INT_ADD:
            _flatten_sum(args[0], sign, terms, size)
            _flatten_sum(args[1], sign, terms, size)
            return
        if mnem == _PCODE_OP.INT_SUB:
            _flatten_sum(args[0], sign, terms, size)
            _flatten_sum(args[1], -sign, terms, size)
            return
        if mnem == _PCODE_OP.INT_AND:
            # Alignment masking, as in MIPS lwl/lwr's addr - (addr & 3).
            # BSID form cannot express masking, so approximate:
            #   x & ~(2^k - 1)  (align down)      ~~> x
            #   x & (2^k - 1)   (remainder bits)  ~~> 0
            # Both move the address by under 2^k, so this holds only while
            # 2^k stays inside the access. Unbounded it rewrote real
            # arithmetic -- a truncating `x & 0xffff` matched the second
            # form, so `base + (x & 0xffff)` silently became `base`.
            const, other = None, None
            for cand, rest in ((args[0], args[1]), (args[1], args[0])):
                if not isinstance(cand, tuple) and _is_const(cand):
                    const, other = cand, rest
                    break
            if const is not None:
                width = int(const.size) * 8
                mask = int(const.offset) & ((1 << width) - 1)
                inv = (~mask) & ((1 << width) - 1)
                # `x & 0` is 0, not x: check it before the align-down test,
                # whose (~0) & (~0 + 1) is 0 in Python's unbounded ints and
                # would otherwise claim the whole mask is a no-op.
                if mask == 0:
                    return
                if inv & (inv + 1) == 0 and inv < size:  # x & ~(2^k-1) ~~> x
                    _flatten_sum(other, sign, terms, size)
                    return
                if mask & (mask + 1) == 0 and mask < size:  # x & (2^k-1) ~~> 0
                    return
                raise UseDefError(
                    f"address masked by {mask:#x}, which spans more than the "
                    f"{size}-byte access: cannot express in base/index/offset "
                    f"form without moving the address"
                )
    terms.append((sign, expr))


def _expr_to_bsid(
    expr: typing.Any,
    ctx: typing.Any,
    size: int,
    addr_size: int,
) -> BSIDMemoryReferenceOperand:
    """Convert a resolved address expression into a
    BSIDMemoryReferenceOperand of the form base + scale*index + offset.

    Handles every addressing shape expressible as a sum of: register,
    signed constant, and register*constant / register<<constant (with
    zext/sext wrappers ignored). Anything else — masked/aligned
    addresses, memory-indirect addresses, negated registers — raises
    UseDefError.
    """
    terms: typing.List[typing.Any] = []
    _flatten_sum(expr, 1, terms, size)

    offset = 0
    plain_regs = []
    scaled = []  # (reg_name, scale)

    for sign, term in terms:
        if isinstance(term, tuple):
            mnem, args = term
            if mnem not in (_PCODE_OP.INT_MULT, _PCODE_OP.INT_LEFT):
                raise UseDefError(f"unsupported address term: {term}")
            a = _unwrap_ext(args[0])
            b = _unwrap_ext(args[1])
            if isinstance(a, tuple) or isinstance(b, tuple):
                raise UseDefError(f"unsupported address term: {term}")
            if _is_const(a) and _is_const(b):
                ca, cb = _const_value(a), _const_value(b)
                prod = (ca << cb) if mnem == _PCODE_OP.INT_LEFT else ca * cb
                offset += sign * prod
                continue
            # canonicalize to (register, constant)
            if _is_const(a) and mnem == _PCODE_OP.INT_MULT:
                a, b = b, a
            if not (_is_register(a) and _is_const(b)):
                raise UseDefError(f"unsupported address term: {term}")
            if sign < 0:
                raise UseDefError(f"negated index register in address: {term}")
            c = _const_value(b)
            scale = (1 << c) if mnem == _PCODE_OP.INT_LEFT else c
            scaled.append((_reg_name(ctx, a), scale))
            continue
        # leaf varnode
        if _is_const(term):
            offset += sign * _const_value(term)
        elif _is_register(term):
            if sign < 0:
                raise UseDefError(f"negated base register in address: {term}")
            plain_regs.append(_reg_name(ctx, term))
        else:
            raise UseDefError(f"unsupported address leaf: {term}")

    base = None
    index = None
    scale = 1
    if len(scaled) > 1:
        raise UseDefError(f"multiple scaled index terms in address: {expr}")
    if scaled:
        index, scale = scaled[0]
    for name in plain_regs:
        if base is None:
            base = name
        elif index is None:
            index = name
        else:
            raise UseDefError(f"too many registers in address: {expr}")

    if base is None and index is None:
        if offset == 0:
            # No base, no index, and a zero displacement: the expression
            # names no location. A well-formed operand always has at
            # least one of base / index / offset, so this is an analysis
            # bug (an address that flattened to nothing), not a real
            # access -- fail loudly instead of silently resolving to
            # address 0. (A genuine absolute [0] reaches use/def as a
            # ram varnode via _varnode_operand, not through here.)
            raise UseDefError(
                f"degenerate memory operand: address {expr!r} has no "
                f"base, index, or offset"
            )
        # pure absolute address: render unsigned at the pointer width
        offset %= 1 << (addr_size * 8)

    return BSIDMemoryReferenceOperand(
        segment=None,
        base=base,
        index=index,
        scale=scale,
        offset=offset,
        size=size,
    )


def _expr_registers(expr, ctx, found):
    """Collect the names of register varnodes appearing in a resolved
    expression, in encounter order.

    Deliberately simpler than `_expr_to_bsid`: the question here is only
    which register a value came from, not what address it forms. An
    indirect branch destination is routinely masked by a *computed*
    constant -- MIPS `jr $t9` resolves to `t9 & INT_2COMP(2)`, clearing the
    ISA-mode bit -- which the address walker rejects because its INT_AND
    case needs a literal.
    """
    if isinstance(expr, tuple):
        if expr[0] == _PCODE_OP.LOAD:
            # The destination is read OUT of memory (`jmp [rax]`, `ret`),
            # so descending would name the ADDRESS register as the code
            # pointer -- one degree of indirection off, and identical to
            # what `jmp rax` reports.
            return found
        for arg in expr[1]:
            _expr_registers(arg, ctx, found)
    elif _is_register(expr):
        name = _reg_name(ctx, expr)
        if name not in found:
            found.append(name)
    return found


class _WrittenSoFar:
    """Register bytes this instruction has already written.

    Membership has to be tested on the varnode's BYTE RANGE, not on the
    register name. Ghidra names a varnode by its own extent, so a write and a
    later read of the same storage under two different names slipped through
    a name comparison and was reported as a genuine use -- fabricating a
    dependency on whatever last wrote it:

      * x86 `mul dh` writes `ax` (the product) and then reads `ah` back to
        set CF/OF, so `ah` was reported as an input. `mul dh` reads only
        `al` and `dh`.
      * AVX `vaddps ymm0, ymm1, ymm2` writes ymm0 as eight lane varnodes
        (named xmm0_d* and ymm0_h) and then reads the whole 32-byte `ymm0`
        for the zmm zero-extension, so `ymm0` was reported as an input of an
        instruction that fully overwrote it.

    The second case is why coverage is tested against the UNION of the writes
    rather than any single one. Full coverage, not overlap, is the right
    test: if every byte the read touches was written by this instruction, the
    read sees the instruction's own value. A read that is only partly covered
    (write `al`, then read `ax`) still consumes bytes from before the
    instruction, so it stays a use.
    """

    def __init__(self) -> None:
        self._bytes: typing.Set[int] = set()

    def add(self, vn) -> None:
        off = int(vn.offset)
        self._bytes.update(range(off, off + int(vn.size)))

    def covers(self, vn) -> bool:
        off = int(vn.offset)
        return self._bytes.issuperset(range(off, off + int(vn.size)))


def _load_store_mem(op, ctx, sstate, size):
    """Memory operand for a LOAD/STORE op's address (input 1)."""
    inputs = op.inputs
    space = _space_name(ctx, inputs[0])
    if space != "ram":
        raise UseDefError(f"{op.opcode.name} to address space {space!r}")
    addr_expr = _resolve_input(inputs[1], sstate)
    return _expr_to_bsid(addr_expr, ctx, size, int(inputs[1].size))


# --------------------------------------------------------------------------- #
# Per-instruction use/def
# --------------------------------------------------------------------------- #


def _instruction_use_def(ctx, ops, disassembly, address):
    """Return (use_set, def_set) for a single machine instruction.

    The sets contain Operand objects:
      * RegisterOperand — Ghidra's size-specific register name,
        lowercased (e.g. 'r1', 'rax', 'cf')
      * BSIDMemoryReferenceOperand — a memory cell whose address is
        rendered as base + scale*index + offset over the register
        values at instruction entry (e.g. stwu r1,-0x30(r1) defines
        the 4-byte cell at [r1 - 0x30]).

    Memory defs come from STORE pcode ops (and direct writes to
    ram-space varnodes); memory uses come from LOAD ops (and direct
    ram-space reads). Register defs come from ops whose output varnode
    is in the register space. Data flow is traced through 'unique'
    varnodes so memory address expressions name the original
    registers, not the pcode temporaries.
    """
    uses = set()
    defs = set()
    written_so_far = _WrittenSoFar()

    sstate = {}

    indirect_targets: typing.List[str] = []
    saw_callother = False
    for op in ops:

        _update_symstate(op, sstate)

        mnemonic = _mnemonic_of(op)

        if mnemonic is _PCODE_OP.CALLOTHER:
            saw_callother = True

        if mnemonic in (_PCODE_OP.UNIMPLEMENTED, _PCODE_OP.INVALID_OP):
            # Ghidra is telling us it has no semantics for this
            # instruction (no SLEIGH definition, or its translation threw).
            # Its inputs and outputs are empty, so the generic path would
            # report "reads nothing, writes nothing" -- indistinguishable
            # from a genuine nop. Say we don't know instead.
            raise UseDefError(
                f"Ghidra reports no p-code semantics ({mnemonic.name}) for "
                f"{disassembly or '<unknown>'} at {address:#x}"
            )

        # A COPY that only shuffles a save/restore bookkeeping register
        # (PPC bl/blr moving the TOC pointer through 'r2Save') is not a
        # real data effect on either side; skip the whole op so neither
        # leaks into the use/def sets. Accumulator internals like ARM
        # mult_addr / PPC tea are deliberately NOT erased here -- their
        # COPY relays a real base register, filtered per-operand below.
        if mnemonic == _PCODE_OP.COPY:
            input0 = _varnode_operand(ctx, op.inputs[0])
            output = _varnode_operand(ctx, op.output)
            names = {o.name for o in (input0, output) if isinstance(o, RegisterOperand)}
            if names & _GHIDRA_COPY_ERASE_REGS:
                continue

        # ---- collect reads from this op's inputs --------------------- #
        # For the direct control-flow ops, input 0 is the destination
        # itself: a ram-space varnode whose *address* is where we go
        # next, not a location whose contents are read. Skip just that
        # input. The indirect forms (BRANCHIND/CALLIND/RETURN) are the
        # opposite: their input's *value* is the destination, so an
        # absolute memory-indirect jump like `jmp [0x1234]`, which
        # Ghidra emits as a bare `BRANCHIND (ram, 0x1234, 8)` with no
        # LOAD op, genuinely reads that pointer out of memory.
        skip_input = (
            0
            if mnemonic in (_PCODE_OP.BRANCH, _PCODE_OP.CBRANCH, _PCODE_OP.CALL)
            else None
        )
        if mnemonic in (
            _PCODE_OP.BRANCHIND,
            _PCODE_OP.CALLIND,
            _PCODE_OP.RETURN,
        ):
            # Input 0's value is where control goes, but the varnode is
            # rarely the architectural register: Ghidra's MIPS `jr $t9` is
            # COPY t9 -> pc then BRANCHIND pc, and resolving that yields
            # `t9 & INT_2COMP(2)` (clearing the ISA-mode bit). Hence
            # resolving through the symbolic state, then collecting
            # registers -- the mask is computed, not a literal, so the
            # address walker rejects it.
            target = _resolve_input(op.inputs[0], sstate)
            regs = [
                name
                for name in _expr_registers(target, ctx, [])
                if not _is_ghidra_internal(name)
            ]
            # Exactly one register, or the destination is computed from
            # several and naming any one of them as "the pointer" would be
            # a guess.
            if len(regs) == 1:
                indirect_targets.append(regs[0])
        # Dependency-breaking idiom: an op whose result is a constant
        # when both inputs are the same register does not genuinely read
        # that register. This is x86's canonical zeroing -- `xor eax,eax`
        # / `sub eax,eax` and the per-lane form of pxor/xorps -- but the
        # test is architecture-neutral. It covers the subtraction/xor
        # itself AND the flag ops that reference the operands directly:
        # `sub` emits INT_SBORROW(eax,eax) *before* the subtract, which
        # would otherwise re-introduce the read. Suppressing these keeps
        # the use/def graph free of a false edge to the register's prior
        # definition; the output is still a def (the register is written,
        # to 0). INT_AND/INT_OR (which return the register) and INT_ADD/
        # carry (which depend on it) are deliberately excluded.
        self_zeroing = (
            mnemonic in _CONST_ON_IDENTICAL_INPUTS
            and len(op.inputs) == 2
            and _same_register(op.inputs[0], op.inputs[1])
        )
        for i, inp in enumerate(op.inputs):
            if i == skip_input:
                continue
            if _is_register(inp):
                if self_zeroing:
                    # spurious self-read; result does not depend on it
                    continue
                reg = _varnode_operand(ctx, inp)
                if _is_ghidra_internal(reg.name):
                    continue
                if written_so_far.covers(inp):
                    continue
                uses.add(reg)
            elif _is_addr(inp):
                # Direct read of a ram-space varnode: absolute or
                # pc-relative addressing that Ghidra resolved at
                # disassembly (no LOAD op is emitted for these).
                mem = _varnode_operand(ctx, inp)
                if mem is not None and mem not in defs:
                    uses.add(mem)

        # ---- STORE: emit a symbolic memory def ----------------------- #
        if mnemonic == _PCODE_OP.STORE:
            inputs = op.inputs
            assert len(inputs) == 3
            mem = _load_store_mem(op, ctx, sstate, int(inputs[2].size))
            defs.add(mem)
            continue  # STORE has no output varnode

        # ---- LOAD: emit a symbolic memory use, propagate value ------- #
        if mnemonic == _PCODE_OP.LOAD:
            inputs = op.inputs
            assert len(inputs) == 2
            out = op.output
            assert not (out is None)
            mem = _load_store_mem(op, ctx, sstate, int(out.size))

            # skip the use if this instruction already stored to the
            # same location (the load reads its own store)
            if not (mem in defs):
                uses.add(mem)
            if not _is_unique(out):
                # loads into a unique need no def; the loaded value is
                # tracked through sstate by _update_symstate
                reg = _varnode_operand(ctx, out)
                if not _is_ghidra_internal(reg.name):
                    defs.add(reg)
                    written_so_far.add(out)
            continue

        # ---- non-STORE/LOAD output handling -------------------------- #
        out = op.output
        if out is None:
            continue
        if _is_unique(out):
            continue
        if _is_addr(out):
            # Direct write to a ram-space varnode: an absolute or
            # pc-relative store that Ghidra resolved at disassembly
            # (no STORE op is emitted for these).
            mem = _varnode_operand(ctx, out)
            defs.add(mem)
            continue
        if not _is_register(out):
            raise UseDefError(f"unsupported output varnode {out} for op {op}")
        reg = _varnode_operand(ctx, out)
        if _is_ghidra_internal(reg.name):
            continue
        defs.add(reg)
        written_so_far.add(out)

    if saw_callother and not uses and not defs:
        # The instruction's entire data effect is hidden inside a CALLOTHER
        # -- p-code's opaque "named user-op" escape hatch, which is how
        # Ghidra models trap instructions (svc, sc, int 0x80, MIPS syscall).
        # Reporting the empty sets would be indistinguishable from a nop; a
        # taint or triage consumer would carry state across a kernel entry
        # as if nothing happened. Instructions where CALLOTHER sits beside
        # real p-code (rdtsc, lock-prefixed RMW, x86-64 syscall's r11/rcx
        # side effects) have non-empty sets and are reported as computed.
        raise UseDefError(
            f"semantics of {disassembly or '<unknown>'} at {address:#x} "
            f"are entirely inside a CALLOTHER (opaque user-op); use/def unknown"
        )
    return uses, defs, tuple(indirect_targets)


# --------------------------------------------------------------------------- #
# Translation                                                                 #
# --------------------------------------------------------------------------- #

# SLEIGH is not documented as thread-safe and a Context holds decoding state,
# so serialize on one lock. RLock because `warm` takes it too.
_analysis_lock = threading.RLock()


def warm(language_id: str) -> None:
    """Build (or reuse) the SLEIGH context for `language_id`.

    Optional -- `analyze` builds it on first use anyway. Call it during setup
    to keep the one-time build out of a latency-sensitive path.
    """
    with _analysis_lock:
        _get_context(language_id)


def _instruction_ops(translation):
    """Split a translation into (imark, body ops) for its first instruction.

    An IMARK introduces each machine instruction and carries its address and
    length; on a delay-slot ISA the branch's IMARK covers the delay slot too
    and its ops are folded in, which is why callers must pad rather than
    supply the real successor. A later IMARK could only mark padding.
    """
    ops = list(translation.ops)
    if not ops or ops[0].opcode != pypcode.OpCode.IMARK:
        return None, []
    body = [op for op in ops[1:] if op.opcode != pypcode.OpCode.IMARK]
    return ops[0], body


def _analyze_inner(byte_data, arch, base_address):
    """Uncached implementation; see analyze for the public API."""
    with _analysis_lock:
        return _analyze_locked(byte_data, arch, base_address)


def _analyze_locked(byte_data, arch, base_address):
    """_analyze_inner's body; runs holding _analysis_lock."""
    ctx = _get_context(arch)
    base = int(base_address)

    # SLEIGH will not form a delay-slot branch (MIPS, SPARC) unless the
    # delay-slot instruction is present, and zeroes decode as a nop there, so
    # the branch's use/def stays its own. Needs no clamping to the address
    # space the way the Ghidra implementation did: nothing is mapped here.
    data = bytes(byte_data) + b"\x00" * 8

    try:
        translation = ctx.translate(data, base, max_instructions=1)
    except pypcode.BadDataError:
        # Nothing decodable here. None rather than an exception: the caller's
        # disassembler may disagree about whether these bytes are an
        # instruction, which is not an error.
        return None
    except pypcode.UnimplError as e:
        # Decoded, but no semantics. Empty sets would read as a nop, so say
        # we do not know -- as the UNIMPLEMENTED op path did before.
        raise UseDefError(f"no p-code semantics for the instruction at {base:#x}: {e}")

    imark, ops = _instruction_ops(translation)
    if imark is None:
        return None

    # First IMARK input is the instruction itself, any others its delay slots.
    # Report its own length; that is what callers check their disassembler on.
    size = int(imark.inputs[0].size)

    try:
        disassembly = ctx.disassemble(data, base, max_instructions=1)
        insn = disassembly.instructions[0]
        text = f"{insn.mnem} {insn.body}".strip()
    except Exception:
        text = ""  # presentation only; never fail an analysis over it

    uses, defs, indirect_targets = _instruction_use_def(ctx, ops, text, base)
    return InstructionUseDef(
        disassembly=text,
        size=size,
        uses=tuple(uses),
        defs=tuple(defs),
        indirect_targets=indirect_targets,
    )


# --------------------------------------------------------------------------- #
# Cached front-door for analyze
# --------------------------------------------------------------------------- #
#
# Each uncached call spins up a Ghidra project, runs BinaryLoader, and
# disassembles -- on the order of seconds. For interactive use where the
# same byte string and arch get analyzed repeatedly (REPL, test loops,
# notebooks), we memoize the result so cache hits cost ~microseconds.
#
# InstructionUseDef holds tuples rather than lists, so a caller cannot
# reshape a cached result for the next hit. (Operand objects inside it are
# still shared and mutable -- see the note on analyze.)

_DEFAULT_CACHE_SIZE = 4096


class _NoInstruction(Exception):
    """Internal: Ghidra decoded nothing at the requested address.

    An exception purely because `lru_cache` memoizes return values but not
    exceptions. A cached None was permanent, and `_pcode_use_def` turns None
    into an empty use/def set -- so a transient miss reported the
    instruction as a no-op forever after. Retrying costs one decode.
    """


@functools.lru_cache(maxsize=_DEFAULT_CACHE_SIZE)
def _analyze_cached(byte_data: bytes, arch: str, base_address: int):
    """Hashable wrapper around _analyze_inner. Its result is an immutable
    NamedTuple, so callers can't mutate cached state. Raises
    _NoInstruction rather than returning None so the miss is not cached."""
    result = _analyze_inner(byte_data, arch, base_address)
    if result is None:
        raise _NoInstruction()
    return result


def analyze(
    byte_data: typing.Union[bytes, bytearray, memoryview],
    arch: str,
    base_address: int = 0,
) -> typing.Optional[InstructionUseDef]:
    """Return the use/def of the instruction at `base_address`.

    `byte_data` must contain that instruction; trailing bytes are ignored
    (and are sometimes necessary -- see the delay-slot note below).
    Returns None if SLEIGH decoded no instruction at `base_address`.

    Two properties of the input are the caller's responsibility:

      * `arch` must be the language the bytes are actually in. Ghidra
        decodes with the language's default context, so a Thumb
        instruction handed to an ARM-mode language id decodes as ARM --
        a valid, entirely different instruction, with no error. Check
        the returned `size` against what your own disassembler found.

      * Trailing bytes after the instruction should be padding, not the
        real successor, on a delay-slot ISA. Ghidra expands a delay slot
        into the branch's own p-code, so a branch followed by its real
        successor reports the pair's combined effects as the branch's.
        Zero padding (which decodes as a nop) keeps a branch's use/def
        its own.

    Caching is layered for speed:

      * Result cache (lru_cache, size 4096): exact-input repeats are
        served from a hashtable in microseconds. Use
        `analyze.cache_clear()` to drop the cache and
        `analyze.cache_info()` to inspect it.

      * Context reuse: one SLEIGH context per architecture, built on
        first use and kept. That build (tens of milliseconds) is the
        only per-architecture cost; translation itself is stateless and
        sub-millisecond. `warm()` moves it off the first analysis.
    """
    # Normalize byte_data so memoryview/bytearray callers also hit the cache
    if not isinstance(byte_data, bytes):
        byte_data = bytes(byte_data)
    try:
        return _analyze_cached(byte_data, arch, int(base_address))
    except _NoInstruction:
        return None


# Expose the lru_cache control surface on the public function so callers
# don't have to know the underscore-prefixed name exists.
analyze.cache_clear = _analyze_cached.cache_clear  # type: ignore[attr-defined]
analyze.cache_info = _analyze_cached.cache_info  # type: ignore[attr-defined]
