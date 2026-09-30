"""The ABI record schema: :class:`ABIDef` and its sub-records.

One frozen :class:`ABIDef` describes one calling convention on one
:class:`~smallworld.platforms.Platform`, keyed ``(platform, variant)``. Records
are deep-immutable: they hold only frozen dataclasses, tuples, ``str``,
``int``, ``bool``, enums and ``None``, so a cached record can be handed to any
caller. Fields that state an ABI fact have no defaults; a sub-record that does
not apply to a record (no FP arguments on a soft-float ABI, no syscall ABI on
bare metal) is ``None`` rather than a partly filled record.

Register naming. Every register is a :class:`RegEntry` with three spellings:
``name`` (the smallworld register the ABI uses, e.g. ``d8``), ``root`` (its
full-width parent in the :class:`~smallworld.platforms.defs.PlatformDef`, e.g.
``q8``) and ``abi_name`` (the psABI spelling). The query methods take
``form="root" | "name" | "abi"`` to choose one. Integer and pointer queries
default to ``root``; FP queries default to ``name``. The predicates accept any
of those spellings, any PlatformDef name for the register, and the entry's
``abi_aliases`` (AArch64 ``ip0``), ignoring case.

Preservation. :class:`Preservation` partitions register bytes (and, for
control/status registers, bits) into callee-saved, caller-saved and neither.
The predicates work on byte ranges after alias folding:

* ``is_callee_saved(x)`` is True when every byte of ``x`` is callee-saved.
* ``is_caller_saved(x)`` is True when any byte of ``x`` is caller-saved.
* otherwise ``x`` is neither, so ``not is_caller_saved(x)`` does not imply
  ``is_callee_saved(x)``.

So on AArch64 ``is_callee_saved("d8")`` is True (the low 8 bytes of ``q8`` are
preserved), ``is_callee_saved("q8")`` is False and ``is_caller_saved("q8")`` is
True (its upper 8 bytes are not). Unknown names answer False and never raise.
"Caller-saved" means "may be clobbered by a conforming external callee", not
"dead after any call".

The name lists (``callee_saved(names_only=True)`` and ``caller_saved(...)``)
agree with the predicates and with ``preservation_of``. In ``form="root"``
(the default) the callee-saved list has a root only when the whole root is
callee-saved, and the caller-saved list has every root with a caller-saved
byte; so AArch64 ``q8`` is caller-saved, not callee-saved. In ``form="name"``
and ``form="abi"`` each entry is listed under its own spelling, so the parts
appear: ``d8`` among the callee-saved names on AArch64.
"""

import dataclasses
import typing

from ..defs.platformdef import PlatformDef, RegisterAliasDef
from ..platforms import ABI, Platform
from .enums import (
    NAME_FORMS,
    Confidence,
    EntryCondition,
    EntryValue,
    FloatABI,
    FloatEncoding,
    FpExhaust,
    FpFile,
    FpIndex,
    FpRoute,
    FpuKind,
    FunctionPointerFormat,
    IntAlloc,
    IntRepr,
    Justify,
    ModeKind,
    PairAlign,
    PairOrder,
    PreservationKind,
    ProcessForm,
    RegClass,
    ReturnKind,
    Role,
    SignalKind,
    Split,
    SretLocation,
    StackPointerTarget,
    SyscallErrorConvention,
    TlsKind,
    UnknownTypePolicy,
    VaListKind,
    VarargsPolicy,
)

# ---------------------------------------------------------------------------
# Registers and the preservation partition
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class RegEntry:
    """One register (or part of one) as an ABI uses it."""

    name: str
    """The smallworld register the ABI uses (``rdi``, ``d8``, ``xmm0``). For an
    unmodeled register, the conventional spelling (``st0``, ``mxcsr``)."""

    root: str
    """The full-width parent of ``name`` in the PlatformDef (``rdi``, ``q8``,
    ``ymm0``); equal to ``name`` for an unmodeled register."""

    offset: int
    """Byte offset inside ``root`` of the bytes the ABI uses, counted as a
    :class:`~smallworld.platforms.defs.RegisterAliasDef` offset is: in the
    memory order of the register's bytes, so the same value can have a
    different offset on the two byte orders."""

    width: int
    """PlatformDef size of ``name`` in bytes (0 if unmodeled)."""

    abi_width: int
    """Number of bytes the ABI uses, starting at ``offset`` (AArch64 ``d8``: 8
    of ``q8``'s 16)."""

    root_width: int
    """PlatformDef size of ``root`` in bytes (0 if unmodeled)."""

    partial: bool
    """True when ``[offset, offset + abi_width)`` does not cover ``root``."""

    abi_name: str
    """The psABI spelling (``%rdi``, ``x30``, ``fs0``). If it is also a
    PlatformDef register name (ignoring case), it must name exactly this
    entry's bytes. An entry for part of a register that has no psABI name
    of its own is spelled as a part: AArch64 ``v8.d[1]``, the upper 8 bytes
    of ``q8``."""

    abi_aliases: typing.Tuple[str, ...]
    """Other spellings of this register that the predicates accept, beyond
    ``name``, ``root``, ``abi_name`` and the PlatformDef's names (AArch64
    ``ip0`` for ``x16``; RISC-V ``fp`` for ``s0``; ARM ``v6``/``tr`` for
    ``r9``; MIPS ``s8``/``fp`` for ``r30``). Matched ignoring case, like
    every spelling."""

    unmodeled: bool
    """True when smallworld does not model this register (``st0``,
    ``mxcsr``). Set queries drop unmodeled entries unless asked; ordered
    argument and return sequences keep them."""

    reg_class: RegClass
    """The register file."""

    roles: typing.Tuple[Role, ...]
    """Why the register is where it is; sorted in :class:`Role` declaration
    order, without duplicates."""

    preserved_mask: typing.Optional[int]
    """For a control/status register split by bits: the bits of this entry's
    byte range that the entry speaks for; ``None`` means every bit.

    Bits count from the least significant bit of the entry's own value: the
    ``abi_width`` bytes at ``offset`` read as one integer in the platform's
    byte order. So a mask does not depend on the byte order, and it must fit
    in ``abi_width`` bytes.

    A register whose bits are preserved differently is recorded as several
    entries over the same bytes (every masked entry of a root has the same
    ``offset`` and ``abi_width``), one per preservation class, and every bit
    of those bytes belongs to exactly one entry. x86 ``mxcsr``, for example,
    is three entries: a callee-saved one with mask ``0xFFC0`` (the control
    bits: rounding, flush-to-zero, exception masks; role ``fp-control``), a
    caller-saved one with mask ``0x003F`` (the sticky status flags), and a
    ``neither`` one with mask ``0xFFFF0000`` (the reserved upper half). ARM,
    SH and PPC ``fpscr`` follow the same pattern. The predicates treat the
    register as a whole: with those entries, ``is_callee_saved("mxcsr")`` is
    False and ``is_caller_saved("mxcsr")`` is True."""

    @property
    def end(self) -> int:
        """One past the last byte (inside ``root``) the ABI uses."""
        return self.offset + self.abi_width

    def has_role(self, role: typing.Union[Role, str]) -> bool:
        return Role(role) in self.roles

    def spelling(self, form: str = "root") -> str:
        """This register in the requested name form."""
        if form == "root":
            return self.root
        if form == "name":
            return self.name
        if form == "abi":
            return self.abi_name
        raise ValueError(
            f"unknown register name form {form!r}; use one of {NAME_FORMS}"
        )


@dataclasses.dataclass(frozen=True)
class Preservation:
    """The preservation partition of a record's register universe.

    Each byte of each root in ``universe`` (or, for entries with a
    ``preserved_mask``, each masked bit) belongs to exactly one of the three
    lists; a bit-split register such as ``mxcsr`` appears once per class, as
    described under :attr:`RegEntry.preserved_mask`.
    Each list is in register-file order: by the position of ``root`` in
    ``universe``, then by ``offset``.
    """

    callee_saved: typing.Tuple[RegEntry, ...]
    caller_saved: typing.Tuple[RegEntry, ...]
    neither: typing.Tuple[RegEntry, ...]
    universe: typing.Tuple[str, ...]
    """Every root the partition covers, in register-file order (the
    PlatformDef's register order, unmodeled roots last)."""


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class IntArgSpec:
    """Integer and pointer argument allocation."""

    registers: typing.Tuple[RegEntry, ...]
    """Integer argument registers in ABI order; ``()`` when stack-only."""

    pointer_registers: typing.Tuple[RegEntry, ...]
    """A separate pointer class (TriCore ``a4..a7``); ``()`` when pointers use
    ``registers``."""

    alloc: IntAlloc
    gpr_width: int
    """Width of an argument GPR in bytes (8 on n32 although ``long`` is 4)."""

    first_n_max_size: int
    """Largest argument eligible for a register under ``FIRST_N`` (4 on MS
    x86); 0 otherwise."""

    pair_align: PairAlign
    split: Split
    close_on_fail: bool
    """Whether a value that does not fit closes the remaining registers."""

    backfill_skipped: bool
    """Whether a later small argument may use a register skipped for
    alignment."""

    wide_on_stack: bool
    """Whether 64-bit arguments always go on the stack (MS fastcall)."""

    pair_order: PairOrder
    ptr_one_reg: bool
    """Whether a pointer always takes exactly one register (MSP430X)."""


@dataclasses.dataclass(frozen=True)
class FpArgSpec:
    """Floating-point argument allocation (``None`` on soft-float records)."""

    registers: typing.Tuple[RegEntry, ...]
    """The allocation unit, one per slot (``xmm0..``, ARM-hf ``s0..s15``)."""

    single_view: typing.Tuple[RegEntry, ...]
    """Single-precision spellings; ``()`` means the same as ``registers``."""

    double_view: typing.Tuple[RegEntry, ...]
    """Double-precision spellings; ``()`` means the same as ``registers``
    unless ``double_pairs`` is set."""

    double_pairs: typing.Tuple[typing.Tuple[RegEntry, RegEntry], ...]
    """Register pairs holding one double (MIPS o32 FR=0)."""

    route: FpRoute
    index: FpIndex
    consumes_int_slot: bool
    exhaust: FpExhaust
    file: FpFile
    backfill: bool
    close_on_stack: bool
    flen: int
    """Widest FP value an FP register holds, in bytes (lp64f: 4)."""

    pair_order: PairOrder
    stack_position: bool
    """Whether FP stack arguments are interleaved with integer ones in
    argument order (True on every current record) rather than grouped."""


# ---------------------------------------------------------------------------
# Stack, varargs, returns
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class StackSpec:
    """Stack layout at a call."""

    alignment: int
    """Stack alignment at the call boundary."""

    entry_bias: int
    """At entry, ``sp % alignment == entry_bias`` (x86-64: 8, the pushed
    return address)."""

    first_arg_offset: int
    """Byte offset from the stack pointer at function entry to the first
    stack-passed argument. It includes everything between the two: the
    return address a pop-ret ABI pushed, and any ``shadow_space``,
    ``linkage_area`` and ``param_save_area``. x86-64 SysV: 8; ms-x64: 40
    (8 return address + 32 shadow space); AArch64: 0; ELFv1: 112 (48 linkage
    area + 64 parameter save area)."""

    slot_size: int
    wide_align: int
    """Alignment of a double-width stack argument."""

    natural: bool
    """Whether stack arguments are naturally aligned rather than slotted."""

    int_justify: Justify
    float_justify: Justify
    float_format: FloatEncoding
    red_zone: int
    shadow_space: int
    """Bytes the caller reserves above the return address for the callee to
    spill register arguments (ms-x64: 32; MIPS o32 home area: 16)."""

    linkage_area: int
    """Bytes of the caller's linkage area at the entry sp (PPC32 SysV: 8;
    ELFv1: 48; ELFv2: 32)."""

    param_save_area: int
    """Bytes of the parameter save area that shadow register-passed
    arguments, before the first stack-passed one (ELFv1/ELFv2: 64)."""

    toc_save_slot: typing.Optional[int]
    reserved_below_sp: int


@dataclasses.dataclass(frozen=True)
class VarargsSignal:
    """A register a variadic caller sets (x86-64 ``al``, PPC32 ``cr1``)."""

    kind: SignalKind
    register: RegEntry
    mask: int


@dataclasses.dataclass(frozen=True)
class VaListField:
    name: str
    offset: int
    size: int


@dataclasses.dataclass(frozen=True)
class VaList:
    """The layout of ``va_list``."""

    kind: VaListKind

    size: int
    fields: typing.Tuple[VaListField, ...]


@dataclasses.dataclass(frozen=True)
class Varargs:
    """Variadic-call rules."""

    policy: VarargsPolicy
    base_standard_scope: typing.Optional[str]
    """With ``BASE_STANDARD``: which values follow the base standard (armhf:
    ``"variadic"``, so variadic doubles go in ``r0:r1``)."""

    variadic_slot: typing.Optional[int]
    """Stack slot size of a variadic argument, when it differs from
    ``StackSpec.slot_size``."""

    signal: typing.Optional[VarargsSignal]
    va_list: typing.Optional[VaList]
    fallback_record: typing.Optional[str]
    """With ``FALLBACK``: the id of the record variadic calls use instead."""


@dataclasses.dataclass(frozen=True)
class ReturnSpec:
    """Where results are returned."""

    int_registers: typing.Tuple[RegEntry, ...]
    """Primary first, then secondaries (``rax, rdx``)."""

    pointer_registers: typing.Tuple[RegEntry, ...]
    """A separate pointer class (m68k ``a0, d0``); ``()`` means the same as
    ``int_registers``."""

    pointer_mirror: typing.Tuple[str, ...]
    """Registers the callee also writes a returned pointer to, besides the
    primary pointer return ``pointer_registers[0]``: m68k returns a pointer
    in ``a0`` and also in ``d0``, so this is ``("d0",)``. PlatformDef
    register names; ``()`` when there is no mirror."""

    fp_registers: typing.Tuple[RegEntry, ...]
    """FP result registers; may include unmodeled entries (``st0``)."""

    fp_single: typing.Optional[RegEntry]
    fp_double: typing.Optional[RegEntry]
    int64_pair: typing.Tuple[RegEntry, ...]
    """A 64-bit result on a 32-bit ABI: the registers in significance
    order."""

    int64_pair_order: PairOrder
    fp_double_pairs: typing.Tuple[typing.Tuple[RegEntry, RegEntry], ...]
    fp_pair_order: PairOrder
    fp_encoding: FloatEncoding
    fp_named: typing.Tuple[typing.Tuple[FloatEncoding, RegEntry], ...]
    """Registers for named float formats (x87-80 in ``st0``)."""

    small_struct_max: int
    """Largest struct returned in registers (0 if none)."""

    small_struct_sizes: typing.Optional[typing.Tuple[int, ...]]
    """If set, only these struct sizes return in registers (ms-x64:
    1, 2, 4, 8); ``None`` means any size up to ``small_struct_max``."""


@dataclasses.dataclass(frozen=True)
class StructReturn:
    """The hidden struct-return pointer."""

    location: SretLocation
    register: typing.Optional[RegEntry]
    arg_class: typing.Optional[RegClass]
    """The argument class whose slot it takes, when it consumes one."""

    consumes_arg_slot: bool
    callee_pops: bool
    echo_register: typing.Optional[RegEntry]
    """The register the callee returns the pointer in (x86-64 ``rax``)."""


@dataclasses.dataclass(frozen=True)
class ExtensionRule:
    """How narrow integers are represented in wider registers and slots."""

    gpr_bits: int
    int32_in_gpr: IntRepr
    uint32_in_gpr: IntRepr
    subint_promote_bits: int
    subint_repr: IntRepr
    bool_repr: IntRepr
    pointer_repr: IntRepr
    return_int32: IntRepr
    stack_slot_repr: IntRepr
    callee_relies: bool
    unknown_type_policy: UnknownTypePolicy
    """How to canonicalize a value of unknown type."""


# ---------------------------------------------------------------------------
# System calls, mechanics, entry state
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class SyscallABI:
    """The Linux system-call ABI (``None`` on Windows and bare metal)."""

    instructions: typing.Tuple[str, ...]
    interrupt: typing.Optional[int]
    number_register: RegEntry
    arg_registers: typing.Tuple[RegEntry, ...]
    stack_args: int
    """Number of arguments passed on the stack after ``arg_registers``."""

    int64_pair_align: PairAlign
    return_register: RegEntry
    return2_register: typing.Optional[RegEntry]
    error_convention: SyscallErrorConvention

    clobbered: typing.Tuple[RegEntry, ...]
    number_base: int
    numbers_family: typing.Optional[str]


@dataclasses.dataclass(frozen=True)
class ExceptionFrame:
    """Hardware exception-entry stacking (M-profile; data only)."""

    registers: typing.Tuple[str, ...]
    alignment: int
    fp_extension: typing.Tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class ReturnMechanics:
    """How a callee finds its return address and returns."""

    kind: ReturnKind
    ra_register: typing.Optional[RegEntry]
    ra_stack_offset: typing.Optional[int]
    ra_size: int
    ra_mask: int
    delay_slot: bool
    callee_cleanup: bool
    thumb_bit: bool
    window_bits: int
    exception_return_prefix: typing.Optional[int]
    exception_frame: typing.Optional[ExceptionFrame]


@dataclasses.dataclass(frozen=True)
class ModeReq:
    """A processor-mode requirement at function entry."""

    register: str
    mask: int
    value: int
    kind: ModeKind
    source: str


@dataclasses.dataclass(frozen=True)
class EntryReg:
    """A register that must hold a particular value at entry."""

    register: RegEntry
    value: EntryValue
    symbol: typing.Optional[str]
    constant: typing.Optional[int]
    when: EntryCondition


@dataclasses.dataclass(frozen=True)
class ProcessEntry:
    """How a process (or a reset image) is entered."""

    form: ProcessForm
    registers: typing.Tuple[EntryReg, ...]
    sp_points_at: StackPointerTarget
    sp_alignment: int


@dataclasses.dataclass(frozen=True)
class EntryState:
    mode: typing.Tuple[ModeReq, ...]
    registers: typing.Tuple[EntryReg, ...]
    process: typing.Optional[ProcessEntry]


@dataclasses.dataclass(frozen=True)
class Tls:
    """Thread-local storage access."""

    kind: TlsKind
    register: typing.Optional[RegEntry]
    descriptor_register: typing.Optional[RegEntry]
    variant: typing.Optional[int]
    """TLS layout variant (1 or 2), if any."""

    tp_offset: int
    tcb_size: int
    dtv_offset: int
    get_addr_symbol: typing.Optional[str]
    get_addr_record: typing.Optional[str]


@dataclasses.dataclass(frozen=True)
class SpecialRegisters:
    stack_pointer: RegEntry
    frame_pointer: typing.Optional[RegEntry]
    frame_pointer_by_isa: typing.Tuple[typing.Tuple[str, RegEntry], ...]
    """Frame pointers that depend on the instruction set (ARM Thumb ``r7``)."""

    global_pointer: typing.Optional[RegEntry]
    gp_bias: int
    tls: typing.Optional[Tls]
    static_chain: typing.Optional[RegEntry]
    pic_call_register: typing.Optional[RegEntry]


@dataclasses.dataclass(frozen=True)
class Linkage:
    """Dynamic-linking roles."""

    scratch: typing.Tuple[RegEntry, ...]
    plt_site_registers: typing.Tuple[EntryReg, ...]
    toc_register: typing.Optional[RegEntry]
    function_pointer_format: FunctionPointerFormat


# ---------------------------------------------------------------------------
# Data model and provenance
# ---------------------------------------------------------------------------

# The C type names below shadow builtins inside the class body, so annotate
# them through an alias that stays unambiguous for type checkers.
_Bytes = int


@dataclasses.dataclass(frozen=True)
class CSizes:
    """``sizeof`` of the C scalar types, in bytes."""

    char: _Bytes
    short: _Bytes
    int: _Bytes
    long: _Bytes
    long_long: _Bytes
    pointer: _Bytes
    size_t: _Bytes
    ssize_t: _Bytes
    ptrdiff_t: _Bytes
    intmax_t: _Bytes
    wchar_t: _Bytes
    wint_t: _Bytes
    float: _Bytes
    double: _Bytes
    long_double: _Bytes


@dataclasses.dataclass(frozen=True)
class CAligns:
    """``_Alignof`` of the C scalar types, in bytes."""

    char: _Bytes
    short: _Bytes
    int: _Bytes
    long: _Bytes
    long_long: _Bytes
    pointer: _Bytes
    size_t: _Bytes
    ssize_t: _Bytes
    ptrdiff_t: _Bytes
    intmax_t: _Bytes
    wchar_t: _Bytes
    wint_t: _Bytes
    float: _Bytes
    double: _Bytes
    long_double: _Bytes


@dataclasses.dataclass(frozen=True)
class DataModel:
    name: str
    """``"LP64"``, ``"ILP32"``, ..."""

    char_signed: bool
    sizes: CSizes
    aligns: CAligns
    long_double_format: FloatEncoding
    wchar_signed: bool
    max_align: int


@dataclasses.dataclass(frozen=True)
class GhidraKeying:
    """Where Ghidra's keying of this record differs from the ABI."""

    deviation_id: str
    field: str
    ghidra_value: str
    abi_value: str
    versions: typing.Optional[str]
    """Ghidra versions the entry applies to (``">=12.0"``); ``None`` means
    the pinned version."""


@dataclasses.dataclass(frozen=True)
class Sources:
    """Where the record's facts come from in external tools."""

    ghidra_language: typing.Optional[str]
    ghidra_compiler: typing.Optional[str]
    ghidra_prototype: typing.Optional[str]
    ghidra_join_klass: typing.Optional[str]
    ghidra_keying: typing.Tuple[GhidraKeying, ...]
    angr_simcc: typing.Optional[str]
    archinfo: typing.Optional[str]


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------

# (root, first byte, one past the last byte)
_Span = typing.Tuple[str, int, int]

_RoleArg = typing.Union[Role, str, typing.Iterable[typing.Union[Role, str]]]
_ClassArg = typing.Union[RegClass, str, typing.Iterable[typing.Union[RegClass, str]]]


#: The register classes whose value-role registers are callee-saved values.
_VALUE_CLASSES = frozenset({RegClass.INT, RegClass.ADDRESS})


def _as_roles(roles: typing.Optional[_RoleArg]) -> typing.Optional[typing.Set[Role]]:
    if roles is None:
        return None
    if isinstance(roles, str):
        return {Role(roles)}
    return {Role(r) for r in roles}


def _as_classes(
    klass: typing.Optional[_ClassArg],
) -> typing.Optional[typing.Set[RegClass]]:
    if klass is None:
        return None
    if isinstance(klass, str):
        return {RegClass(klass)}
    return {RegClass(k) for k in klass}


def _check_form(form: str) -> None:
    if form not in NAME_FORMS:
        raise ValueError(
            f"unknown register name form {form!r}; use one of {NAME_FORMS}"
        )


def _platformdef_spans(platdef: PlatformDef) -> typing.Dict[str, _Span]:
    """Every register of `platdef`, folded through its aliases to the byte
    span it occupies in its root."""
    registers = platdef.registers
    spans: typing.Dict[str, _Span] = {}
    for name, reg in registers.items():
        root, offset = name, 0
        seen = {name}
        while isinstance(reg, RegisterAliasDef) and reg.parent in registers:
            offset += reg.offset
            root = reg.parent
            if root in seen:
                break
            seen.add(root)
            reg = registers[root]
        spans[name] = (root, offset, offset + registers[name].size)
    return spans


def _names(entries: typing.Iterable[RegEntry], form: str) -> typing.Tuple[str, ...]:
    """Spell `entries` in `form`, deduplicated, keeping the first occurrence."""
    _check_form(form)
    seen: typing.Dict[str, None] = {}
    for entry in entries:
        seen.setdefault(entry.spelling(form), None)
    return tuple(seen)


@dataclasses.dataclass(frozen=True, eq=False, repr=False)
class ABIDef:
    """One calling convention on one platform.

    Records compare and hash by ``id`` and pickle (and copy and deep-copy)
    as a reference to the registry record with that id, so ``copy.copy``,
    ``copy.deepcopy`` and an unpickle all return that registry record. A
    record that is not the registry's own (a :func:`dataclasses.replace`
    copy, or one built by hand) raises ``TypeError`` instead. Look records
    up with :func:`smallworld.platforms.abi.resolve` and the other module
    functions rather than constructing them.
    """

    # --- identity -------------------------------------------------------
    id: str
    """``"<ARCHITECTURE>/<BYTEORDER>:<variant>"``, e.g.
    ``"X86_64/LITTLE:sysv"``."""

    platform: Platform
    variant: str
    """Kebab-case name, unique within the platform (``sysv``, ``aapcs64``)."""

    abi_id: str
    """A label shared by records of the same convention (``amd64-psabi/sysv``)."""

    family: str
    abi: typing.Optional[ABI]
    """The coarse :class:`~smallworld.platforms.ABI` family, or ``None`` for a
    convention reachable only by variant (``regparm3``, ``go-abiinternal``)."""

    is_default: bool
    """Whether this is the platform's default record."""

    is_family_default: bool
    """Whether this is what ``resolve(platform, abi)`` returns for ``abi``."""

    per_function: bool
    toolchain: str
    confidence: Confidence

    # --- conventions ----------------------------------------------------
    int_args: IntArgSpec
    fp_args: typing.Optional[FpArgSpec]
    stack: StackSpec
    varargs: Varargs
    returns: ReturnSpec
    sret: typing.Optional[StructReturn]
    extension: ExtensionRule
    preservation: Preservation
    special: SpecialRegisters
    return_mechanics: ReturnMechanics
    entry: EntryState
    float_abi: FloatABI
    fpu: FpuKind
    data_model: DataModel
    linkage: Linkage
    os_abi: typing.Optional[str]
    syscall: typing.Optional[SyscallABI]
    view_windowed_callinc: int
    """Xtensa windowed: the call increment of the pre-entry view; 0 on
    non-windowed records."""

    sources: Sources

    def __post_init__(self) -> None:
        # Private, lazily filled memo of derived lookup tables. It is not a
        # field, so it takes no part in equality, repr or pickling.
        object.__setattr__(self, "_memo", {})

    # --- identity semantics ---------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ABIDef):
            return NotImplemented
        return self.id == other.id

    def __hash__(self) -> int:
        return hash(self.id)

    def __repr__(self) -> str:
        return f"ABIDef({self.id!r})"

    def __reduce__(self):
        # Pickling, copy.copy and copy.deepcopy all come through here. A
        # record reduces to its id, so only the registry's own record can
        # round-trip; anything else (a dataclasses.replace() copy, a
        # hand-built record) would silently come back as the registry's.
        from . import registry
        from .errors import ABITablesUnavailable

        try:
            registered = registry.by_id(self.id)
        except (ValueError, ABITablesUnavailable) as e:
            raise TypeError(
                f"cannot pickle or copy {self!r}: it is not a registry record, "
                "and records pickle and copy only as a reference to the "
                "registry record with their id"
            ) from e
        if registered is not self:
            raise TypeError(
                f"cannot pickle or copy {self!r}: it is not the registry "
                "record with that id (a modified or hand-built record), and "
                "records pickle and copy only as a reference to the registry "
                "record with their id"
            )
        return (registry.by_id, (self.id,))

    @property
    def key(self) -> typing.Tuple[Platform, str]:
        return (self.platform, self.variant)

    # --- internal lookup tables -----------------------------------------

    def _memoized(self, key: str, build: typing.Callable[[], typing.Any]) -> typing.Any:
        memo: typing.Dict[str, typing.Any] = self._memo  # type: ignore[attr-defined]
        if key not in memo:
            memo[key] = build()
        return memo[key]

    def _partition(
        self,
    ) -> typing.Tuple[typing.Tuple[PreservationKind, RegEntry], ...]:
        """Every partition entry with its class, in register-file order."""

        def build():
            p = self.preservation
            tagged = (
                [(PreservationKind.CALLEE_SAVED, e) for e in p.callee_saved]
                + [(PreservationKind.CALLER_SAVED, e) for e in p.caller_saved]
                + [(PreservationKind.NEITHER, e) for e in p.neither]
            )
            order = {root: i for i, root in enumerate(p.universe)}
            last = len(order)
            # sorted() is stable, so ties keep callee, caller, neither order.
            tagged.sort(key=lambda ke: (order.get(ke[1].root, last), ke[1].offset))
            return tuple(tagged)

        return self._memoized("partition", build)

    def _by_root(
        self,
    ) -> typing.Dict[str, typing.Tuple[typing.Tuple[PreservationKind, RegEntry], ...]]:
        def build():
            table: typing.Dict[str, typing.List] = {}
            for kind, entry in self._partition():
                table.setdefault(entry.root, []).append((kind, entry))
            return {root: tuple(v) for root, v in table.items()}

        return self._memoized("by_root", build)

    def _spellings(self) -> typing.Dict[str, _Span]:
        """Every accepted spelling of a register, mapped to its byte span."""

        def build():
            table: typing.Dict[str, _Span] = {}
            # Spellings the record itself knows: abi names, unmodeled
            # registers, and anything the PlatformDef lacks. Where several
            # entries share a spelling, the span covers all of them.
            for _, entry in self._partition():
                for spelling in (
                    entry.abi_name,
                    *entry.abi_aliases,
                    entry.name,
                    entry.root,
                ):
                    span = (entry.root, entry.offset, entry.end)
                    old = table.get(spelling)
                    if old is not None and old[0] == entry.root:
                        span = (entry.root, min(old[1], span[1]), max(old[2], span[2]))
                    table[spelling] = span
            # The PlatformDef is authoritative for every modeled name.
            try:
                platdef = PlatformDef.for_platform(self.platform)
            except ValueError:
                return table
            table.update(_platformdef_spans(platdef))
            return table

        return self._memoized("spellings", build)

    def _folded_spellings(self) -> typing.Dict[str, typing.Optional[_Span]]:
        """:meth:`_spellings` keyed by casefolded spelling; ``None`` where two
        spellings that differ only in case name different spans."""

        def build():
            table: typing.Dict[str, typing.Optional[_Span]] = {}
            for spelling, span in self._spellings().items():
                key = spelling.casefold()
                if key in table and table[key] != span:
                    table[key] = None
                else:
                    table[key] = span
            return table

        return self._memoized("folded_spellings", build)

    def _locate(self, name: str) -> typing.Optional[_Span]:
        """The byte span `name` spells, matching exactly first and then
        ignoring case; ``None`` if it is unknown or ambiguous."""
        if not isinstance(name, str):
            return None
        span = self._spellings().get(name)
        if span is None:
            span = self._folded_spellings().get(name.casefold())
        return span

    def _overlapping(
        self, span: _Span
    ) -> typing.Tuple[typing.Tuple[PreservationKind, RegEntry], ...]:
        root, lo, hi = span
        return tuple(
            (kind, entry)
            for kind, entry in self._by_root().get(root, ())
            if entry.offset < hi and lo < entry.end
        )

    @staticmethod
    def _covers(span: _Span, entries: typing.Iterable[RegEntry]) -> bool:
        _, lo, hi = span
        for entry in sorted(entries, key=lambda e: e.offset):
            if entry.offset > lo:
                return False
            lo = max(lo, entry.end)
            if lo >= hi:
                return True
        return lo >= hi

    # --- arguments ------------------------------------------------------

    def int_arg_registers(self, form: str = "root") -> typing.Tuple[str, ...]:
        """Integer argument registers in ABI order; ``()`` means stack-only."""
        return _names(self.int_args.registers, form)

    def pointer_arg_registers(self, form: str = "root") -> typing.Tuple[str, ...]:
        """Pointer argument registers in ABI order.

        These differ from :meth:`int_arg_registers` only on records with a
        separate pointer class (TriCore ``a4..a7``).
        """
        registers = self.int_args.pointer_registers or self.int_args.registers
        return _names(registers, form)

    def _fp_slots(
        self, precision: typing.Optional[str]
    ) -> typing.Tuple[typing.Tuple[RegEntry, ...], ...]:
        fp = self.fp_args
        if fp is None:
            return ()
        if precision is None:
            if fp.double_pairs and not fp.double_view:
                # The allocation unit is the pair (MIPS o32 FR=0).
                return tuple(tuple(pair) for pair in fp.double_pairs)
            return tuple((e,) for e in fp.registers)
        if precision == "single":
            return tuple((e,) for e in (fp.single_view or fp.registers))
        if precision == "double":
            if fp.double_view:
                return tuple((e,) for e in fp.double_view)
            if fp.double_pairs:
                return tuple(tuple(pair) for pair in fp.double_pairs)
            return tuple((e,) for e in fp.registers)
        raise ValueError(
            f"unknown FP precision {precision!r}; use None, 'single' or 'double'"
        )

    @typing.overload
    def fp_arg_registers(  # noqa: E704 (black's stub style)
        self,
        precision: typing.Optional[str] = ...,
        form: str = ...,
        pieces: typing.Literal[False] = ...,
    ) -> typing.Tuple[str, ...]: ...

    @typing.overload
    def fp_arg_registers(  # noqa: E704 (black's stub style)
        self,
        precision: typing.Optional[str] = ...,
        form: str = ...,
        *,
        pieces: typing.Literal[True],
    ) -> typing.Tuple[typing.Tuple[str, ...], ...]: ...

    def fp_arg_registers(
        self,
        precision: typing.Optional[str] = None,
        form: str = "name",
        pieces: bool = False,
    ) -> typing.Union[
        typing.Tuple[str, ...], typing.Tuple[typing.Tuple[str, ...], ...]
    ]:
        """FP argument registers in ABI order.

        Arguments:
            precision: ``None`` for the allocation unit (one per slot),
                ``"single"`` or ``"double"`` for that precision's view.
            form: ``"name"`` (default), ``"root"`` or ``"abi"``.
            pieces: return one tuple of registers per slot (a pair for a
                double held in two registers) instead of one name per slot.

        On records whose FP index is the argument position (MS x64), entry
        *i* is the register for argument position *i*.
        """
        slots = self._fp_slots(precision)
        if pieces:
            _check_form(form)
            return tuple(tuple(e.spelling(form) for e in slot) for slot in slots)
        return _names((slot[0] for slot in slots), form)

    # --- returns --------------------------------------------------------

    def int_return_registers(self, form: str = "root") -> typing.Tuple[str, ...]:
        """Integer result registers: the primary first, then secondaries."""
        return _names(self.returns.int_registers, form)

    def pointer_return_registers(self, form: str = "root") -> typing.Tuple[str, ...]:
        """Pointer result registers (m68k ``a0``; TriCore ``a2``); the
        integer ones where there is no separate pointer class. Registers
        that only mirror the pointer (m68k ``d0``) are
        ``returns.pointer_mirror``."""
        registers = self.returns.pointer_registers or self.returns.int_registers
        return _names(registers, form)

    def primary_return_registers(self, form: str = "root") -> typing.Tuple[str, ...]:
        """The primary integer result register, then the primary pointer
        result register if it differs (m68k ``d0, a0``; x86-64 ``rax``)."""
        primary: typing.List[RegEntry] = []
        if self.returns.int_registers:
            primary.append(self.returns.int_registers[0])
        if self.returns.pointer_registers:
            primary.append(self.returns.pointer_registers[0])
        return _names(primary, form)

    def fp_return_registers(self, form: str = "name") -> typing.Tuple[str, ...]:
        """FP result registers in ABI order, unmodeled ones included
        (i386: ``("st0",)``)."""
        return _names(self.returns.fp_registers, form)

    # --- preservation ---------------------------------------------------

    def _whole_root_in(self, root: str, kind: PreservationKind) -> bool:
        """Whether every partition entry of `root` is of class `kind`."""
        return all(k is kind for k, _ in self._by_root().get(root, ()))

    def _select(
        self,
        kind: PreservationKind,
        entries: typing.Tuple[RegEntry, ...],
        roles: typing.Optional[_RoleArg],
        exclude: typing.Iterable[str],
        klass: typing.Optional[_ClassArg],
        form: str,
        names_only: bool,
        include_unmodeled: bool,
    ) -> typing.Union[typing.Tuple[RegEntry, ...], typing.Tuple[str, ...]]:
        _check_form(form)
        wanted_roles = _as_roles(roles)
        wanted_classes = _as_classes(klass)
        # A lone string is one name, not an iterable of one-letter names.
        excluded_names = {exclude} if isinstance(exclude, str) else set(exclude)
        excluded_roots = set()
        for name in excluded_names:
            span = self._locate(name)
            if span is not None:
                excluded_roots.add(span[0])
        selected = tuple(
            e
            for e in entries
            if (include_unmodeled or not e.unmodeled)
            and (wanted_roles is None or wanted_roles.intersection(e.roles))
            and (wanted_classes is None or e.reg_class in wanted_classes)
            and e.name not in excluded_names
            and e.root not in excluded_roots
        )
        if names_only:
            if form == "root" and kind is PreservationKind.CALLEE_SAVED:
                # A callee-saved root is listed only if all of it is; a root
                # with any caller-saved byte is caller-saved, as
                # is_caller_saved() and preservation_of() say.
                selected = tuple(
                    e for e in selected if self._whole_root_in(e.root, kind)
                )
            return _names(selected, form)
        return selected

    @typing.overload
    def callee_saved(  # noqa: E704 (black's stub style)
        self,
        *,
        roles: typing.Optional[_RoleArg] = ...,
        exclude: typing.Iterable[str] = ...,
        klass: typing.Optional[_ClassArg] = ...,
        form: str = ...,
        names_only: typing.Literal[False] = ...,
        include_unmodeled: bool = ...,
    ) -> typing.Tuple[RegEntry, ...]: ...

    @typing.overload
    def callee_saved(  # noqa: E704 (black's stub style)
        self,
        *,
        roles: typing.Optional[_RoleArg] = ...,
        exclude: typing.Iterable[str] = ...,
        klass: typing.Optional[_ClassArg] = ...,
        form: str = ...,
        names_only: typing.Literal[True],
        include_unmodeled: bool = ...,
    ) -> typing.Tuple[str, ...]: ...

    def callee_saved(
        self,
        *,
        roles: typing.Optional[_RoleArg] = None,
        exclude: typing.Iterable[str] = (),
        klass: typing.Optional[_ClassArg] = None,
        form: str = "root",
        names_only: bool = False,
        include_unmodeled: bool = False,
    ) -> typing.Union[typing.Tuple[RegEntry, ...], typing.Tuple[str, ...]]:
        """Callee-saved partition entries, in register-file order.

        Arguments:
            roles: keep entries carrying any of these roles.
            exclude: drop entries whose name or root is any of these
                spellings (a spelling excludes its whole root); a single
                name may be passed as a string.
            klass: keep entries of this register class (or classes).
            form: name form when ``names_only`` is set. With ``"root"``
                :meth:`callee_saved` lists a root only if the whole root is
                callee-saved, so a partly preserved register (AArch64
                ``q8``) is left out; ``"name"`` and ``"abi"`` list each
                entry's own spelling (``d8``).
            names_only: return deduplicated names instead of entries.
            include_unmodeled: keep unmodeled entries (``mxcsr``).
        """
        return self._select(
            PreservationKind.CALLEE_SAVED,
            self.preservation.callee_saved,
            roles,
            exclude,
            klass,
            form,
            names_only,
            include_unmodeled,
        )

    @typing.overload
    def caller_saved(  # noqa: E704 (black's stub style)
        self,
        *,
        roles: typing.Optional[_RoleArg] = ...,
        exclude: typing.Iterable[str] = ...,
        klass: typing.Optional[_ClassArg] = ...,
        form: str = ...,
        names_only: typing.Literal[False] = ...,
        include_unmodeled: bool = ...,
    ) -> typing.Tuple[RegEntry, ...]: ...

    @typing.overload
    def caller_saved(  # noqa: E704 (black's stub style)
        self,
        *,
        roles: typing.Optional[_RoleArg] = ...,
        exclude: typing.Iterable[str] = ...,
        klass: typing.Optional[_ClassArg] = ...,
        form: str = ...,
        names_only: typing.Literal[True],
        include_unmodeled: bool = ...,
    ) -> typing.Tuple[str, ...]: ...

    def caller_saved(
        self,
        *,
        roles: typing.Optional[_RoleArg] = None,
        exclude: typing.Iterable[str] = (),
        klass: typing.Optional[_ClassArg] = None,
        form: str = "root",
        names_only: bool = False,
        include_unmodeled: bool = False,
    ) -> typing.Union[typing.Tuple[RegEntry, ...], typing.Tuple[str, ...]]:
        """Caller-saved partition entries, in register-file order.

        Takes the same arguments as :meth:`callee_saved`. Caller-saved means
        "a conforming external callee may clobber it". In ``form="root"``
        every root with a caller-saved byte is listed, as
        :meth:`is_caller_saved` answers: AArch64 ``q8`` is, because its upper
        8 bytes are.
        """
        return self._select(
            PreservationKind.CALLER_SAVED,
            self.preservation.caller_saved,
            roles,
            exclude,
            klass,
            form,
            names_only,
            include_unmodeled,
        )

    def callee_saved_values(self) -> typing.Tuple[str, ...]:
        """Roots of the integer and address registers that hold
        callee-saved values.

        This is the set a consumer may treat as "never an input": it
        includes the frame pointer and PIC-convention GOT registers, and the
        value registers of a separate address file (TriCore ``a12..a15``);
        it excludes the stack pointer, psABI-reserved global/TOC/platform/link
        registers, TLS and FP/vector registers.
        """
        return _names(
            (
                e
                for e in self.preservation.callee_saved
                if not e.unmodeled
                and e.reg_class in _VALUE_CLASSES
                and Role.VALUE in e.roles
            ),
            "root",
        )

    def is_callee_saved(self, name: str) -> bool:
        """Whether every byte of `name` is callee-saved.

        Accepts any spelling, ignoring case (``ebx`` or ``EBX`` on X86_64
        folds to ``rbx``; AArch64 ``ip0`` to ``x16``). Unknown names answer
        False.
        """
        span = self._locate(name)
        if span is None:
            return False
        overlapping = self._overlapping(span)
        if not overlapping:
            return False
        if any(kind is not PreservationKind.CALLEE_SAVED for kind, _ in overlapping):
            return False
        return self._covers(span, (e for _, e in overlapping))

    def is_callee_saved_value(self, name: str) -> bool:
        """Whether `name` lies entirely in a callee-saved value register.

        Like :meth:`is_callee_saved`, restricted to what
        :meth:`callee_saved_values` returns: on AArch64 ``d8`` is callee-saved
        but not a callee-saved value.
        """
        if not self.is_callee_saved(name):
            return False
        span = self._locate(name)
        assert span is not None
        return all(
            e.reg_class in _VALUE_CLASSES and Role.VALUE in e.roles
            for _, e in self._overlapping(span)
        )

    def is_caller_saved(self, name: str) -> bool:
        """Whether any byte of `name` is caller-saved. Unknown names answer
        False."""
        span = self._locate(name)
        if span is None:
            return False
        return any(
            kind is PreservationKind.CALLER_SAVED for kind, _ in self._overlapping(span)
        )

    def is_reserved(self, name: str) -> bool:
        """Whether any byte of `name` belongs to an entry with the
        ``reserved`` role."""
        span = self._locate(name)
        if span is None:
            return False
        return any(Role.RESERVED in e.roles for _, e in self._overlapping(span))

    def preservation_of(self, name: str) -> typing.Optional[PreservationKind]:
        """The class of `name`: callee-saved if every byte is, else
        caller-saved if any byte is, else neither. ``None`` for a name that
        is unknown or outside the partition."""
        span = self._locate(name)
        if span is None or not self._overlapping(span):
            return None
        if self.is_callee_saved(name):
            return PreservationKind.CALLEE_SAVED
        if self.is_caller_saved(name):
            return PreservationKind.CALLER_SAVED
        return PreservationKind.NEITHER

    def registers_with_role(
        self,
        role: typing.Union[Role, str],
        *,
        form: str = "root",
        include_unmodeled: bool = False,
    ) -> typing.Tuple[str, ...]:
        """Names of partition entries with `role`, in register-file order."""
        wanted = Role(role)
        return _names(
            (
                e
                for _, e in self._partition()
                if wanted in e.roles and (include_unmodeled or not e.unmodeled)
            ),
            form,
        )

    def reserved(self, *, form: str = "root") -> typing.Tuple[str, ...]:
        """Registers with the ``reserved`` role, in register-file order."""
        return self.registers_with_role(Role.RESERVED, form=form)

    # --- special registers ----------------------------------------------

    def _root_of(self, name: str) -> typing.Optional[str]:
        span = self._locate(name)
        return span[0] if span is not None else None

    @property
    def stack_pointer(self) -> str:
        """The stack pointer's root."""
        return self.special.stack_pointer.root

    def is_stack_pointer(self, name: str) -> bool:
        """Whether `name` is (a view of) the stack pointer."""
        return self._root_of(name) == self.stack_pointer

    @property
    def frame_pointer(self) -> typing.Optional[str]:
        """The frame pointer's root, if the ABI names one."""
        fp = self.special.frame_pointer
        return fp.root if fp is not None else None

    def frame_pointer_for(self, isa: str) -> typing.Optional[str]:
        """The frame pointer's root for instruction set `isa` (ARM
        ``"thumb"``), falling back to :attr:`frame_pointer`."""
        for key, entry in self.special.frame_pointer_by_isa:
            if key == isa:
                return entry.root
        return self.frame_pointer

    def frame_pointers(self) -> typing.Tuple[str, ...]:
        """Every frame-pointer root the ABI names, deduplicated."""
        entries: typing.List[RegEntry] = []
        if self.special.frame_pointer is not None:
            entries.append(self.special.frame_pointer)
        entries.extend(entry for _, entry in self.special.frame_pointer_by_isa)
        return _names(entries, "root")

    def is_frame_pointer(self, name: str) -> bool:
        root = self._root_of(name)
        return root is not None and root in self.frame_pointers()

    @property
    def link_register(self) -> typing.Optional[str]:
        """The return-address register's root, if the ABI uses one."""
        ra = self.return_mechanics.ra_register
        return ra.root if ra is not None else None

    @property
    def global_pointer(self) -> typing.Optional[str]:
        gp = self.special.global_pointer
        return gp.root if gp is not None else None

    @property
    def thread_pointer(self) -> typing.Optional[str]:
        tls = self.special.tls
        if tls is None or tls.register is None:
            return None
        return tls.register.root

    @property
    def static_chain(self) -> typing.Optional[str]:
        chain = self.special.static_chain
        return chain.root if chain is not None else None


__all__ = [
    "ABIDef",
    "CAligns",
    "CSizes",
    "DataModel",
    "EntryReg",
    "EntryState",
    "ExceptionFrame",
    "ExtensionRule",
    "FpArgSpec",
    "GhidraKeying",
    "IntArgSpec",
    "Linkage",
    "ModeReq",
    "Preservation",
    "ProcessEntry",
    "RegEntry",
    "ReturnMechanics",
    "ReturnSpec",
    "SpecialRegisters",
    "Sources",
    "StackSpec",
    "StructReturn",
    "SyscallABI",
    "Tls",
    "VaList",
    "VaListField",
    "Varargs",
    "VarargsSignal",
]
