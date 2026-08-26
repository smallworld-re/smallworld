"""
Compute use/def sets for machine instructions using Ghidra's raw pcode,
via pyghidra.

For each machine instruction we ask Ghidra for its pcode translation and
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

import atexit
import functools
import logging
import threading
import typing
from enum import Enum, auto

from smallworld.instructions import Operand, RegisterOperand
from smallworld.instructions.bsid import BSIDMemoryReferenceOperand

logger = logging.getLogger(__name__)

_pyghidra_started = False


def _prepare_symz3_extension():
    """Best-effort: extract Ghidra's SymbolicSummaryZ3 extension (and add its
    native libraries to the loader path) *before* we boot the JVM.

    Ghidra only discovers extensions while its Application initializes, during
    the first ``pyghidra.start()`` in the process. When our use/def analysis is
    that first starter, a :class:`GhidraSymbolicEmulator` constructed later can
    no longer load the extension (its own loader would run too late). Preparing
    it here keeps both consumers working regardless of which boots the JVM
    first. Does nothing when the symbolic extension isn't available (e.g. a
    base install without the Ghidra symbolic emulator)."""
    try:
        from smallworld.emulators.ghidra import symz3_loader

        symz3_loader.prepare_extension()
    except Exception as e:
        # The extension is optional; use/def must work without it. Any failure
        # here (no install dir, missing extension, unsupported Ghidra) just
        # means a later GhidraSymbolicEmulator will report the problem itself.
        # Logged rather than swallowed outright: this catch is broad enough to
        # hide the extension going missing entirely -- an AttributeError from a
        # renamed symz3_loader API looks exactly like "no extension installed".
        logger.debug(f"not preparing the SymZ3 extension: {e!r}")


def _ensure_pyghidra():
    """Boot the embedded JVM on first use rather than at import time, so
    that importing smallworld doesn't pay Ghidra's multi-second startup
    (pyghidra.start() is idempotent; the flag just skips the call).

    pyghidra is imported here rather than at module scope: it lives behind
    the optional 'emu-ghidra' extra, and a module that cannot even be
    imported on a base install forces every caller -- and every test that
    only wants the pure-Python parts of this module -- to guard the import
    itself. Returns the module so callers need not re-import it.
    """
    global _pyghidra_started
    import pyghidra

    # atexit is LIFO, so our teardown must be registered AFTER jpype's (which
    # `import pyghidra` installs) to run BEFORE it -- otherwise the JVM is
    # already down when we close the cached programs and the process never
    # exits. Registering here makes that order explicit; at module scope it
    # held only by accident of the import sitting above it.
    _register_shutdown_hook()

    if not _pyghidra_started:
        _prepare_symz3_extension()
        pyghidra.start()
        _pyghidra_started = True
    return pyghidra


# Per-language cache of (offset, size, Register) for register-space
# registers, used to find the smallest named register containing a
# varnode when no register starts at the varnode's address (e.g. the
# upper-lane zeroing writes AArch64 emits at z0+8, or x0+4).
_register_intervals: dict = {}


def _containing_register(program, vn):
    key = str(program.getLanguageID())
    intervals = _register_intervals.get(key)
    if intervals is None:
        intervals = []
        for reg in program.getLanguage().getRegisters():
            addr = reg.getAddress()
            if not addr.getAddressSpace().isRegisterSpace():
                continue
            # getNumBytes(), not bitLength // 8, which truncates for any
            # register that is not a whole number of bytes (MIPS ext_off16_s
            # is 16 bits across 3). Too short an interval makes containment
            # reject a varnode genuinely inside the register.
            size = max(1, int(reg.getNumBytes()))
            intervals.append((int(addr.getOffset()), size, reg))
        _register_intervals[key] = intervals
    off = int(vn.getAddress().getOffset())
    size = int(vn.getSize())
    best = None
    for koff, ksize, reg in intervals:
        if koff <= off and off + size <= koff + ksize:
            if best is None or ksize < best[1]:
                best = (koff, ksize, reg)
    return best[2] if best else None


def _reg_name(program, vn):
    """Name (lowercase) of the register a register-space varnode denotes.

    Prefers the exactly-sized register at the varnode's address ("eax"
    vs "rax"), then any register starting there, then the smallest
    named register containing the varnode's byte range.
    """
    reg = program.getRegister(vn.getAddress(), vn.getSize())
    if reg is None:
        reg = program.getRegister(vn.getAddress())
    if reg is None:
        reg = _containing_register(program, vn)
    if reg is None:
        raise UseDefError(f"no register found for varnode {vn}")
    return reg.getName().lower()


def _varnode_operand(program, vn):

    # returning None seems to signal that this is neither a Reg nor memory.
    if vn is None:
        return None
    if vn.isConstant():
        return None
    if vn.isUnique():
        return None

    if vn.isRegister():
        return RegisterOperand(_reg_name(program, vn))

    # Anything left has to be a concrete address. UseDefError rather than
    # assert: `python -O` strips asserts, which would silently report some
    # other memory space as ram.
    if not vn.isAddress():
        raise UseDefError(f"varnode {vn} is in no space this analysis models")
    addr = vn.getAddress()
    space = addr.getAddressSpace().getName()
    if space != "ram":
        # isAddress() is true for every ram-TYPE space, not only the one named
        # "ram"; Harvard/DSP languages define several (CODE/DATA/SFR/...).
        raise UseDefError(f"memory varnode in address space {space!r}")
    return BSIDMemoryReferenceOperand(
        segment=None,
        base=None,
        index=None,
        scale=1,
        # Java's getOffset() is a signed long; addresses are unsigned
        offset=int(addr.getOffset()) & ((1 << 64) - 1),
        size=int(vn.getSize()),
    )


def _unique_key(vn):
    """Hashable key for a unique-space varnode."""
    return (int(vn.getAddress().getOffset()), int(vn.getSize()))


def _same_register(a, b):
    """True if two varnodes denote the exact same register (same
    register-space offset and size)."""
    return (
        a.isRegister()
        and b.isRegister()
        and a.getAddress().getOffset() == b.getAddress().getOffset()
        and a.getSize() == b.getSize()
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
    # Ghidra's PcodeOp mnemonics for these are bare CEIL/FLOOR/ROUND, not
    # FLOAT_*; the enum is looked up BY NAME, so the spelling is load-bearing.
    CEIL = auto()
    FLOOR = auto()
    ROUND = auto()
    FLOAT_NAN = auto()
    INT2FLOAT = auto()
    FLOAT2FLOAT = auto()
    TRUNC = auto()
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
    # SPULL/ZPULL appear in stack-machine languages; INVALID_OP and
    # UNIMPLEMENTED are Ghidra's markers for "no semantics available" --
    # see the UseDefError raised for them in _instruction_use_def.
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
    name = str(op.getMnemonic())
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


def _space_name(program, space_id_vn):
    """STORE/LOAD encode the destination address space in input[0],
    which is a 'constant' varnode whose value is the space id."""
    space_id = int(space_id_vn.getOffset())
    space = program.getAddressFactory().getAddressSpace(space_id)
    return space.getName() if space is not None else f"space{space_id}"


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
    if inp.isUnique():
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
            if not isinstance(k, tuple):
                continue
            koff, ksize = k
            if koff <= off and off + size <= koff + ksize:
                return val
        raise UseDefError(f"unique read before write: {inp}")
    if inp.isRegister():
        if inp in sstate:
            # Register assigned earlier in this instruction: a read now
            # sees the value this instruction computed, not the
            # instruction input.
            return sstate[inp]
        # same sub-range logic as uniques, for partial register reads
        # of a register this instruction already wrote
        off = int(inp.getAddress().getOffset())
        size = int(inp.getSize())
        for k, val in sstate.items():
            if isinstance(k, tuple) or not k.isRegister():
                continue
            koff = int(k.getAddress().getOffset())
            ksize = int(k.getSize())
            if koff <= off and off + size <= koff + ksize:
                return val
        return inp
    # const, ram address, or register still holding its entry value
    return inp


def _update_symstate(op, sstate):
    # resolve all inputs (args) to this op in terms of
    # inputs-to-the-instruction, and then record
    # mapping from out to that resolution
    ris = [_resolve_input(inp, sstate) for inp in op.getInputs()]
    # special case! There's no need for an s-expr. This is basically
    # just an assignment
    mnemonic = _mnemonic_of(op)
    if mnemonic == _PCODE_OP.COPY:
        assert (len(ris)) == 1
        val = ris[0]
    else:
        val = (mnemonic, ris)
    outp = op.getOutput()
    if outp is None:
        # no output to track (e.g. STORE, branches)
        return
    if outp.isUnique():
        sstate[_unique_key(outp)] = val
    elif outp.isRegister():
        sstate[outp] = val
    # else: output is a ram address (absolute store via COPY); nothing
    # downstream reads it back through sstate, so don't track it


def _const_value(vn):
    """Value of a constant varnode, interpreted as signed at its size.

    Java's getOffset() returns a signed 64-bit long, so mask to the
    varnode's width first, then sign-interpret at that width.
    """
    size = int(vn.getSize())
    if size < 1 or size > 8:
        return int(vn.getOffset())
    width = size * 8
    val = int(vn.getOffset()) & ((1 << width) - 1)
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
                if not isinstance(cand, tuple) and cand.isConstant():
                    const, other = cand, rest
                    break
            if const is not None:
                width = int(const.getSize()) * 8
                mask = int(const.getOffset()) & ((1 << width) - 1)
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
    program: typing.Any,
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
            if a.isConstant() and b.isConstant():
                ca, cb = _const_value(a), _const_value(b)
                prod = (ca << cb) if mnem == _PCODE_OP.INT_LEFT else ca * cb
                offset += sign * prod
                continue
            # canonicalize to (register, constant)
            if a.isConstant() and mnem == _PCODE_OP.INT_MULT:
                a, b = b, a
            if not (a.isRegister() and b.isConstant()):
                raise UseDefError(f"unsupported address term: {term}")
            if sign < 0:
                raise UseDefError(f"negated index register in address: {term}")
            c = _const_value(b)
            scale = (1 << c) if mnem == _PCODE_OP.INT_LEFT else c
            scaled.append((_reg_name(program, a), scale))
            continue
        # leaf varnode
        if term.isConstant():
            offset += sign * _const_value(term)
        elif term.isRegister():
            if sign < 0:
                raise UseDefError(f"negated base register in address: {term}")
            plain_regs.append(_reg_name(program, term))
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


def _expr_registers(expr, program, found):
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
            _expr_registers(arg, program, found)
    elif expr.isRegister():
        name = _reg_name(program, expr)
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
        off = int(vn.getAddress().getOffset())
        self._bytes.update(range(off, off + int(vn.getSize())))

    def covers(self, vn) -> bool:
        off = int(vn.getAddress().getOffset())
        return self._bytes.issuperset(range(off, off + int(vn.getSize())))


def _load_store_mem(op, program, sstate, size):
    """Memory operand for a LOAD/STORE op's address (input 1)."""
    inputs = op.getInputs()
    space = _space_name(program, inputs[0])
    if space != "ram":
        raise UseDefError(f"{op.getMnemonic()} to address space {space!r}")
    addr_expr = _resolve_input(inputs[1], sstate)
    return _expr_to_bsid(addr_expr, program, size, int(inputs[1].getSize()))


# --------------------------------------------------------------------------- #
# Per-instruction use/def
# --------------------------------------------------------------------------- #


def _instruction_use_def(program, instr):
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
    for op in instr.getPcode():

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
                f"{instr.getMnemonicString()} at {instr.getAddress()}"
            )

        # A COPY that only shuffles a save/restore bookkeeping register
        # (PPC bl/blr moving the TOC pointer through 'r2Save') is not a
        # real data effect on either side; skip the whole op so neither
        # leaks into the use/def sets. Accumulator internals like ARM
        # mult_addr / PPC tea are deliberately NOT erased here -- their
        # COPY relays a real base register, filtered per-operand below.
        if mnemonic == _PCODE_OP.COPY:
            input0 = _varnode_operand(program, op.getInput(0))
            output = _varnode_operand(program, op.getOutput())
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
            target = _resolve_input(op.getInput(0), sstate)
            regs = [
                name
                for name in _expr_registers(target, program, [])
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
            and len(op.getInputs()) == 2
            and _same_register(op.getInput(0), op.getInput(1))
        )
        for i, inp in enumerate(op.getInputs()):
            if i == skip_input:
                continue
            if inp.isRegister():
                if self_zeroing:
                    # spurious self-read; result does not depend on it
                    continue
                reg = _varnode_operand(program, inp)
                if _is_ghidra_internal(reg.name):
                    continue
                if written_so_far.covers(inp):
                    continue
                uses.add(reg)
            elif inp.isAddress():
                # Direct read of a ram-space varnode: absolute or
                # pc-relative addressing that Ghidra resolved at
                # disassembly (no LOAD op is emitted for these).
                mem = _varnode_operand(program, inp)
                if mem is not None and mem not in defs:
                    uses.add(mem)

        # ---- STORE: emit a symbolic memory def ----------------------- #
        if mnemonic == _PCODE_OP.STORE:
            inputs = op.getInputs()
            assert len(inputs) == 3
            mem = _load_store_mem(op, program, sstate, int(inputs[2].getSize()))
            defs.add(mem)
            continue  # STORE has no output varnode

        # ---- LOAD: emit a symbolic memory use, propagate value ------- #
        if mnemonic == _PCODE_OP.LOAD:
            inputs = op.getInputs()
            assert len(inputs) == 2
            out = op.getOutput()
            assert not (out is None)
            mem = _load_store_mem(op, program, sstate, int(out.getSize()))

            # skip the use if this instruction already stored to the
            # same location (the load reads its own store)
            if not (mem in defs):
                uses.add(mem)
            if not out.isUnique():
                # loads into a unique need no def; the loaded value is
                # tracked through sstate by _update_symstate
                reg = _varnode_operand(program, out)
                if not _is_ghidra_internal(reg.name):
                    defs.add(reg)
                    written_so_far.add(out)
            continue

        # ---- non-STORE/LOAD output handling -------------------------- #
        out = op.getOutput()
        if out is None:
            continue
        if out.isUnique():
            continue
        if out.isAddress():
            # Direct write to a ram-space varnode: an absolute or
            # pc-relative store that Ghidra resolved at disassembly
            # (no STORE op is emitted for these).
            mem = _varnode_operand(program, out)
            defs.add(mem)
            continue
        if not out.isRegister():
            raise UseDefError(f"unsupported output varnode {out} for op {op}")
        reg = _varnode_operand(program, out)
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
            f"semantics of {instr.getMnemonicString()} at {instr.getAddress()} "
            f"are entirely inside a CALLOTHER (opaque user-op); use/def unknown"
        )
    return uses, defs, tuple(indirect_targets)


# --------------------------------------------------------------------------- #
# Long-lived program cache (one open Ghidra program per architecture)
# --------------------------------------------------------------------------- #
#
# Spinning up a fresh Ghidra project + BinaryLoader pipeline costs ~150-350 ms
# per call; the actual disassembly + use/def of a 4-byte instruction is sub-ms.
# To amortize the setup cost across many cold-path calls (cache misses on the
# result lru_cache above), we keep one `pyghidra.open_program` context alive
# per architecture and repopulate its single memory block on each call. We
# bypass the context manager's __exit__ for the lifetime of the process and
# rely on an atexit hook for graceful teardown.

# language_id (str) -> (open_program-cm, flat_api, addr_space)
# Guarded by _analysis_lock; see its comment below.
_program_cache: dict = {}


def _get_or_create_program(arch):
    """Return (flat_api, program, addr_space) for a long-lived program
    of the given architecture, creating it on the first call."""
    pyghidra = _ensure_pyghidra()
    entry = _program_cache.get(arch)
    if entry is not None:
        _cm, flat_api, space = entry
        return flat_api, flat_api.getCurrentProgram(), space

    # First time we've seen this arch: open a fresh program around a
    # one-byte placeholder file. We manually __enter__ the context and
    # stash it; teardown happens at atexit (or on eviction after error).
    import os
    import tempfile

    fd, placeholder = tempfile.mkstemp(suffix=".bin", prefix="usedef-init-")
    try:
        os.write(fd, b"\x00")
        os.close(fd)
        cm = pyghidra.open_program(
            placeholder,
            language=arch,
            loader="ghidra.app.util.opinion.BinaryLoader",
            analyze=False,
        )
        flat_api = cm.__enter__()
    finally:
        try:
            os.unlink(placeholder)
        except OSError:
            pass

    # Everything from here to the cache insert has to close the program on
    # failure: the entry is not in _program_cache yet, so the caller's
    # _evict_program finds nothing and the Ghidra project stays open -- holding
    # its directory lock -- for the life of the process, once per retry.
    try:
        program = flat_api.getCurrentProgram()
        # Capture the address space BinaryLoader used so per-call blocks
        # land in the same space (rather than guessing at default-space
        # semantics, which can differ between languages).
        initialized = [b for b in program.getMemory().getBlocks() if b.isInitialized()]
        if not initialized:
            raise RuntimeError(
                f"BinaryLoader produced no initialized blocks for {arch!r}"
            )
        space = initialized[0].getStart().getAddressSpace()
    except BaseException:
        try:
            cm.__exit__(None, None, None)
        except Exception:
            pass
        raise

    _program_cache[arch] = (cm, flat_api, space)
    return flat_api, program, space


def _evict_program(arch):
    """Drop a cached program — used after an error left it in a bad
    state, or proactively before process exit."""
    with _analysis_lock:
        entry = _program_cache.pop(arch, None)
        if entry is None:
            return
        cm, _flat_api, _space = entry
        # The interval table holds Java Register handles belonging to THIS
        # program; keeping them past teardown both leaks them and matches
        # future varnodes against objects from a closed program.
        _register_intervals.pop(arch, None)
        try:
            cm.__exit__(None, None, None)
        except Exception:
            # Best-effort teardown; the JVM may already be torn down.
            pass


_shutdown_hook_registered = False


def _register_shutdown_hook():
    """Install `_shutdown_program_cache` at atexit, once. See the ordering
    note in `_ensure_pyghidra`."""
    global _shutdown_hook_registered
    if not _shutdown_hook_registered:
        atexit.register(_shutdown_program_cache)
        _shutdown_hook_registered = True


def _shutdown_program_cache():
    # Via _evict_program so teardown happens under _analysis_lock, and so
    # there is one implementation of "close a cached program". SmallWorld runs
    # emulation callbacks on daemon threads (emulators/panda/panda.py), which
    # the interpreter does NOT join before running atexit handlers, so without
    # the lock this could close a program a worker was mid-way through
    # repopulating.
    for lang_id in list(_program_cache):
        _evict_program(lang_id)


def _java_offset(value: int) -> int:
    """`value` as Java sees it: Address offsets cross the boundary as a signed
    64-bit long, so anything at or above 2**63 -- every x86-64 kernel address
    (0xffffffff81000000), every AArch64 kernel address (0xffff800000000000) --
    raises `OverflowError: int too big to convert` from JPype. That is not a
    UseDefError, so it escaped the reads/writes property AND tripped
    _analyze_locked's generic handler, evicting the shared per-architecture
    program (a 200 ms - 2 s rebuild) once per such instruction."""
    value &= (1 << 64) - 1
    if value >= 1 << 63:
        value -= 1 << 64
    return value


def _populate_program(program, addr_space, byte_data, base_address):
    """Swap whatever bytes are currently loaded for `byte_data` at
    `base_address`, then disassemble the new range."""
    import jpype
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.program.model.address import AddressSet
    from ghidra.util.task import TaskMonitor
    from java.io import ByteArrayInputStream

    memory = program.getMemory()
    listing = program.getListing()

    tx = program.startTransaction("usedef-repopulate")
    try:
        # 1. Wipe everything. Clear code units first so removeBlock has
        #    nothing to complain about, then drop the block.
        for block in list(memory.getBlocks()):
            try:
                listing.clearCodeUnits(block.getStart(), block.getEnd(), False)
            except Exception:
                # Non-fatal: removeBlock will still handle it for typical
                # raw-binary blocks.
                pass
            memory.removeBlock(block, TaskMonitor.DUMMY)

        # 2. Create a fresh initialized block holding the new bytes at
        #    the requested base, in the same address space BinaryLoader
        #    originally chose.
        addr = addr_space.getAddress(_java_offset(int(base_address)))
        # Java bytes are signed (-128..127); convert 0..255 explicitly so
        # jpype doesn't choke on values above 0x7f.
        signed = [(b - 256 if b >= 128 else b) for b in byte_data]
        jbytes = jpype.JArray(jpype.JByte)(signed)
        stream = ByteArrayInputStream(jbytes)
        memory.createInitializedBlock(
            "code",
            addr,
            stream,
            len(byte_data),
            TaskMonitor.DUMMY,
            False,
        )

        # 3. Disassemble the full range of the new block.
        block = memory.getBlock(addr)
        addr_set = AddressSet(block.getStart(), block.getEnd())
        DisassembleCommand(addr_set, addr_set, True).applyTo(
            program,
            TaskMonitor.DUMMY,
        )
    finally:
        program.endTransaction(tx, True)


#: Serializes the cold path: `_populate_program` mutates the one cached
#: program per architecture in place, and lru_cache does not serialize the
#: call it wraps. Re-entrant because the error path calls _evict_program,
#: which takes it too.
#:
#: Results are correct from any thread, but if the FIRST analysis for an
#: architecture runs on a worker thread the process then fails to exit
#: (right answer in ~6 s, still running at 5 min; ~9 s and clean from the
#: main thread). Not our teardown and not JPype -- it is Ghidra's own
#: machinery behind open_program -- so warm each architecture from the main
#: thread.
_analysis_lock = threading.RLock()


def _pad_room(addr_space, base_address, length, want=8):
    """How many padding bytes fit after `length` bytes at `base_address`
    without running past the end of `addr_space`."""
    try:
        mask = (1 << 64) - 1
        space_max = int(addr_space.getMaxAddress().getOffset()) & mask
        end = (int(base_address) & mask) + length
        return max(0, min(want, space_max + 1 - end))
    except Exception:
        # If Ghidra will not tell us the extent, keep the old behaviour.
        return want


def _analyze_inner(byte_data, arch, base_address):
    """Uncached implementation; see analyze for the public API.

    Reuses a long-lived Ghidra program per architecture rather than
    tearing it down between calls. On any error we evict the cached
    program so a subsequent call rebuilds it cleanly rather than
    inheriting a half-initialized state.
    """
    with _analysis_lock:
        return _analyze_locked(byte_data, arch, base_address)


def _analyze_locked(byte_data, arch, base_address):
    """_analyze_inner's body; runs holding _analysis_lock."""
    try:
        flat_api, program, addr_space = _get_or_create_program(arch)
        # Pad with zero bytes so instructions at the end of the buffer
        # that need a successor to disassemble still decode — Ghidra
        # refuses to form a delay-slot branch (MIPS, SPARC) unless the
        # delay-slot instruction is present in memory. Instructions
        # decoded inside the padding are filtered out of the results.
        #
        # Clamped to what is left of the space: a fixed 8 bytes overran the
        # top of a 32-bit space for an instruction near the end (a reset
        # vector, a high trampoline), and Ghidra raised a Java
        # AddressOverflowException.
        pad = b"\x00" * _pad_room(addr_space, base_address, len(byte_data))
        _populate_program(program, addr_space, byte_data + pad, base_address)

        # Look the instruction up *at* the requested address rather than
        # taking whatever decoded first, so the result is always the
        # instruction the caller asked about. Anything Ghidra decoded in
        # the padding (or after this instruction) is ignored.
        instr = program.getListing().getInstructionAt(
            addr_space.getAddress(_java_offset(int(base_address)))
        )
        if instr is None:
            return None
        uses, defs, indirect_targets = _instruction_use_def(program, instr)
        return InstructionUseDef(
            disassembly=instr.toString(),
            size=int(instr.getLength()),
            uses=tuple(uses),
            defs=tuple(defs),
            indirect_targets=indirect_targets,
        )
    except UseDefError:
        # Raised by the pure-Python walk over already-decoded p-code, which
        # runs after _populate_program's transaction has closed -- the
        # program is fine, this instruction is simply one we cannot express.
        # Evicting here would throw away a program every other caller on
        # this architecture is reusing and re-pay the 200 ms - 2 s rebuild,
        # and lru_cache never memoizes exceptions, so a retry pays it again.
        raise
    except Exception:
        # Anything else may have left the program half-mutated (the
        # removeBlock / createInitializedBlock window in _populate_program
        # is the case that actually can), so rebuild it next time.
        _evict_program(arch)
        raise


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
    instruction as a no-op forever after. Retrying costs one decode against
    an open program (~1 ms).
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
    Returns None if Ghidra decoded no instruction at `base_address`.

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

      * Program reuse: per architecture, we hold one Ghidra program
        open for the lifetime of the process and reload its memory
        block on each cold-path call instead of spinning up a fresh
        project. The first call per architecture pays the one-time
        SLEIGH / BinaryLoader cost (~200 ms to ~2 s depending on the
        ISA); subsequent calls swap bytes through `Memory.removeBlock`
        / `createInitializedBlock` in ~1 ms. Cached programs are torn
        down by an atexit hook; if an analysis errors out, the
        affected program is evicted so the next call rebuilds it.
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
