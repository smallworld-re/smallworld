"""Hand-written ABI records for the smallworld.platforms.abi unit tests.

These stand in for the generated tables, which are not part of the source
tree. They are transcribed from smallworld's own calling contexts
(``state/models/amd64/systemv/systemv.py``, ``aarch64/systemv/systemv.py``)
and the psABIs, and carry just enough of each partition to exercise the query
API. They are test data, not the shipped values: the generated module spells
every constructor out, while this file uses small helpers to stay readable.

``RECORDS`` has the same shape as the generated module's, so a test can
serve it with ``registry._use_records(RECORDS)`` or install this module as the
data module.
"""

import dataclasses
import typing

from smallworld.platforms import ABI, Architecture, Byteorder, Platform
from smallworld.platforms.abi import (
    ABIDef,
    CAligns,
    Confidence,
    CSizes,
    DataModel,
    EntryCondition,
    EntryReg,
    EntryState,
    EntryValue,
    ExtensionRule,
    FloatABI,
    FloatEncoding,
    FpArgSpec,
    FpExhaust,
    FpFile,
    FpIndex,
    FpRoute,
    FpuKind,
    FunctionPointerFormat,
    IntAlloc,
    IntArgSpec,
    IntRepr,
    Justify,
    Linkage,
    PairAlign,
    PairOrder,
    Preservation,
    PreservationKind,
    ProcessEntry,
    ProcessForm,
    RegClass,
    RegEntry,
    ReturnKind,
    ReturnMechanics,
    ReturnSpec,
    Role,
    SignalKind,
    Sources,
    SpecialRegisters,
    Split,
    SretLocation,
    StackPointerTarget,
    StackSpec,
    StructReturn,
    SyscallABI,
    SyscallErrorConvention,
    Tls,
    TlsKind,
    UnknownTypePolicy,
    VaList,
    VaListField,
    VaListKind,
    Varargs,
    VarargsPolicy,
    VarargsSignal,
)

X86_64 = Platform(Architecture.X86_64, Byteorder.LITTLE)
AARCH64 = Platform(Architecture.AARCH64, Byteorder.LITTLE)
TRICORE = Platform(Architecture.TRICORE, Byteorder.LITTLE)

CALLEE = PreservationKind.CALLEE_SAVED
CALLER = PreservationKind.CALLER_SAVED
NEITHER = PreservationKind.NEITHER

INT = RegClass.INT
ADDRESS = RegClass.ADDRESS
FP = RegClass.FP
VEC = RegClass.VECTOR
FLAGS = RegClass.FLAGS
SPECIAL = RegClass.SPECIAL
SYSTEM = RegClass.SYSTEM

_ROLE_ORDER = list(Role)


def _roles(roles: typing.Iterable[Role]) -> typing.Tuple[Role, ...]:
    return tuple(sorted(set(roles), key=_ROLE_ORDER.index))


def full(
    name: str,
    size: int,
    klass: RegClass,
    *roles: Role,
    abi_name: typing.Optional[str] = None,
    aliases: typing.Tuple[str, ...] = (),
) -> RegEntry:
    """A whole root register."""
    return RegEntry(
        name=name,
        root=name,
        offset=0,
        width=size,
        abi_width=size,
        root_width=size,
        partial=False,
        abi_name=abi_name or name,
        abi_aliases=aliases,
        unmodeled=False,
        reg_class=klass,
        roles=_roles(roles),
        preserved_mask=None,
    )


def part(
    name: str,
    root: str,
    width: int,
    root_width: int,
    klass: RegClass,
    *roles: Role,
    offset: int = 0,
    abi_width: typing.Optional[int] = None,
    abi_name: typing.Optional[str] = None,
) -> RegEntry:
    """Part of a root: `name` is `width` bytes, the ABI uses `abi_width`
    bytes of it starting at `offset` inside `root`."""
    abi_width = width if abi_width is None else abi_width
    return RegEntry(
        name=name,
        root=root,
        offset=offset,
        width=width,
        abi_width=abi_width,
        root_width=root_width,
        partial=not (offset == 0 and abi_width == root_width),
        abi_name=abi_name or name,
        abi_aliases=(),
        unmodeled=False,
        reg_class=klass,
        roles=_roles(roles),
        preserved_mask=None,
    )


def unmodeled(
    name: str,
    abi_width: int,
    klass: RegClass,
    *roles: Role,
    mask: typing.Optional[int] = None,
) -> RegEntry:
    """A register smallworld does not model."""
    return RegEntry(
        name=name,
        root=name,
        offset=0,
        width=0,
        abi_width=abi_width,
        root_width=0,
        partial=False,
        abi_name=name,
        abi_aliases=(),
        unmodeled=True,
        reg_class=klass,
        roles=_roles(roles),
        preserved_mask=mask,
    )


def partition(
    entries: typing.Sequence[typing.Tuple[PreservationKind, RegEntry]],
) -> Preservation:
    """A Preservation from ``(kind, entry)`` pairs in register-file order."""
    universe: typing.Dict[str, None] = {}
    for _, entry in entries:
        universe.setdefault(entry.root, None)
    return Preservation(
        callee_saved=tuple(e for k, e in entries if k is CALLEE),
        caller_saved=tuple(e for k, e in entries if k is CALLER),
        neither=tuple(e for k, e in entries if k is NEITHER),
        universe=tuple(universe),
    )


def lp64_data_model(
    char_signed: bool, long_double: FloatEncoding, wchar_signed: bool
) -> DataModel:
    sizes = dict(
        char=1,
        short=2,
        int=4,
        long=8,
        long_long=8,
        pointer=8,
        size_t=8,
        ssize_t=8,
        ptrdiff_t=8,
        intmax_t=8,
        wchar_t=4,
        wint_t=4,
        float=4,
        double=8,
        long_double=16,
    )
    return DataModel(
        name="LP64",
        char_signed=char_signed,
        sizes=CSizes(**sizes),
        aligns=CAligns(**sizes),
        long_double_format=long_double,
        wchar_signed=wchar_signed,
        max_align=16,
    )


# ---------------------------------------------------------------------------
# X86_64/LITTLE:sysv (AMD64 psABI; AMD64SysVCallingContext)
# ---------------------------------------------------------------------------

# In PlatformDef (register-file) order.
_GPR_NAMES = "rax rbx rcx rdx r8 r9 r10 r11 r12 r13 r14 r15 rdi rsi rsp rbp".split()
_GPR = {n: full(n, 8, INT, abi_name="%" + n) for n in _GPR_NAMES}
_XMM = [part(f"xmm{i}", f"ymm{i}", 16, 32, VEC, abi_name=f"%xmm{i}") for i in range(16)]
_AL = part("al", "rax", 1, 8, INT, abi_name="%al")


def _x86_64_partition(windows: bool) -> Preservation:
    callee_gprs = {"rbx", "rbp", "r12", "r13", "r14", "r15"}
    if windows:
        callee_gprs |= {"rdi", "rsi"}
    entries: typing.List[typing.Tuple[PreservationKind, RegEntry]] = []
    for name, entry in _GPR.items():
        if name == "rsp":
            roles: typing.Tuple[Role, ...] = (Role.STACK_POINTER,)
            entries.append((CALLEE, full(name, 8, INT, *roles, abi_name="%rsp")))
        elif name == "rbp":
            roles = (Role.VALUE, Role.FRAME_POINTER)
            entries.append((CALLEE, full(name, 8, INT, *roles, abi_name="%rbp")))
        elif name in callee_gprs:
            entries.append(
                (CALLEE, full(name, 8, INT, Role.VALUE, abi_name="%" + name))
            )
        else:
            entries.append((CALLER, entry))
    entries.append((CALLER, full("rflags", 8, FLAGS, Role.CONDITION)))
    entries.extend((CALLER, full(f"fpr{i}", 10, FP)) for i in range(8))
    entries.append((CALLEE, full("fctrl", 2, SPECIAL, Role.FP_CONTROL)))
    entries.append((CALLER, full("fstat", 2, SPECIAL)))
    entries.append((NEITHER, full("fsbase", 8, SYSTEM, Role.TLS)))
    for i in range(16):
        if windows and i >= 6:
            # ms-x64: xmm6-xmm15 are preserved; the upper ymm halves are not.
            entries.append(
                (CALLEE, part(f"xmm{i}", f"ymm{i}", 16, 32, VEC, Role.FP_VALUE))
            )
            entries.append(
                (
                    CALLER,
                    part(
                        f"ymm{i}",
                        f"ymm{i}",
                        32,
                        32,
                        VEC,
                        offset=16,
                        abi_width=16,
                        abi_name=f"%ymm{i}[255:128]",
                    ),
                )
            )
        else:
            entries.append((CALLER, full(f"ymm{i}", 32, VEC)))
    # mxcsr: control bits are preserved, status flags are not.
    entries.append(
        (CALLEE, unmodeled("mxcsr", 4, SPECIAL, Role.FP_CONTROL, mask=0xFFC0))
    )
    entries.append((CALLER, unmodeled("mxcsr", 4, SPECIAL, mask=0x003F)))
    # The reserved upper half belongs to no preserved class.
    entries.append((NEITHER, unmodeled("mxcsr", 4, SPECIAL, mask=0xFFFF0000)))
    return partition(entries)


X86_64_SYSV = ABIDef(
    id="X86_64/LITTLE:sysv",
    platform=X86_64,
    variant="sysv",
    abi_id="amd64-psabi/sysv",
    family="amd64-psabi",
    abi=ABI.SYSTEMV,
    is_default=True,
    is_family_default=True,
    per_function=False,
    toolchain="gcc",
    confidence=Confidence.HIGH,
    int_args=IntArgSpec(
        registers=tuple(_GPR[n] for n in ("rdi", "rsi", "rdx", "rcx", "r8", "r9")),
        pointer_registers=(),
        alloc=IntAlloc.SEQUENTIAL,
        gpr_width=8,
        first_n_max_size=0,
        pair_align=PairAlign.NONE,
        split=Split.NEVER,
        close_on_fail=False,
        backfill_skipped=False,
        wide_on_stack=False,
        pair_order=PairOrder.MEMORY,
        ptr_one_reg=False,
    ),
    fp_args=FpArgSpec(
        registers=tuple(_XMM[:8]),
        single_view=(),
        double_view=(),
        double_pairs=(),
        route=FpRoute.FPR,
        index=FpIndex.OWN,
        consumes_int_slot=False,
        exhaust=FpExhaust.STACK,
        file=FpFile.COUNTER,
        backfill=False,
        close_on_stack=False,
        flen=8,
        pair_order=PairOrder.MEMORY,
        stack_position=True,
    ),
    stack=StackSpec(
        alignment=16,
        entry_bias=8,
        first_arg_offset=8,
        slot_size=8,
        wide_align=16,
        natural=False,
        int_justify=Justify.LEFT,
        float_justify=Justify.LEFT,
        float_format=FloatEncoding.IEEE,
        red_zone=128,
        shadow_space=0,
        linkage_area=0,
        param_save_area=0,
        toc_save_slot=None,
        reserved_below_sp=0,
    ),
    varargs=Varargs(
        policy=VarargsPolicy.SAME,
        base_standard_scope=None,
        variadic_slot=None,
        signal=VarargsSignal(kind=SignalKind.VECTOR_COUNT, register=_AL, mask=0xFF),
        va_list=VaList(
            kind=VaListKind.STRUCT,
            size=24,
            fields=(
                VaListField("gp_offset", 0, 4),
                VaListField("fp_offset", 4, 4),
                VaListField("overflow_arg_area", 8, 8),
                VaListField("reg_save_area", 16, 8),
            ),
        ),
        fallback_record=None,
    ),
    returns=ReturnSpec(
        int_registers=(_GPR["rax"], _GPR["rdx"]),
        pointer_registers=(),
        pointer_mirror=(),
        fp_registers=(_XMM[0], _XMM[1]),
        fp_single=_XMM[0],
        fp_double=_XMM[0],
        int64_pair=(),
        int64_pair_order=PairOrder.MEMORY,
        fp_double_pairs=(),
        fp_pair_order=PairOrder.MEMORY,
        fp_encoding=FloatEncoding.IEEE,
        fp_named=((FloatEncoding.X87_80, unmodeled("st0", 10, FP)),),
        small_struct_max=16,
        small_struct_sizes=None,
    ),
    sret=StructReturn(
        location=SretLocation.REGISTER,
        register=_GPR["rdi"],
        arg_class=INT,
        consumes_arg_slot=True,
        callee_pops=False,
        echo_register=_GPR["rax"],
    ),
    extension=ExtensionRule(
        gpr_bits=64,
        int32_in_gpr=IntRepr.UNSPECIFIED,
        uint32_in_gpr=IntRepr.UNSPECIFIED,
        subint_promote_bits=32,
        subint_repr=IntRepr.BY_TYPE,
        bool_repr=IntRepr.ZERO,
        pointer_repr=IntRepr.UNSPECIFIED,
        return_int32=IntRepr.UNSPECIFIED,
        stack_slot_repr=IntRepr.UNSPECIFIED,
        callee_relies=True,
        unknown_type_policy=UnknownTypePolicy.IDENTITY,
    ),
    preservation=_x86_64_partition(windows=False),
    special=SpecialRegisters(
        stack_pointer=_GPR["rsp"],
        frame_pointer=_GPR["rbp"],
        frame_pointer_by_isa=(),
        global_pointer=None,
        gp_bias=0,
        tls=Tls(
            kind=TlsKind.BASE_REGISTER,
            register=full("fsbase", 8, SYSTEM),
            descriptor_register=_GPR["rax"],
            variant=2,
            tp_offset=0,
            tcb_size=0,
            dtv_offset=8,
            get_addr_symbol="__tls_get_addr",
            get_addr_record=None,
        ),
        static_chain=_GPR["r10"],
        pic_call_register=None,
    ),
    return_mechanics=ReturnMechanics(
        kind=ReturnKind.POP_RET,
        ra_register=None,
        ra_stack_offset=0,
        ra_size=8,
        ra_mask=0xFFFFFFFFFFFFFFFF,
        delay_slot=False,
        callee_cleanup=False,
        thumb_bit=False,
        window_bits=0,
        exception_return_prefix=None,
        exception_frame=None,
    ),
    entry=EntryState(
        mode=(),
        registers=(),
        process=ProcessEntry(
            form=ProcessForm.SYSV_STACK,
            registers=(
                EntryReg(
                    register=_GPR["rdx"],
                    value=EntryValue.ZERO,
                    symbol=None,
                    constant=None,
                    when=EntryCondition.ALWAYS,
                ),
            ),
            sp_points_at=StackPointerTarget.ARGC,
            sp_alignment=16,
        ),
    ),
    float_abi=FloatABI.HARD,
    fpu=FpuKind.X87_SSE,
    data_model=lp64_data_model(True, FloatEncoding.X87_80, True),
    linkage=Linkage(
        scratch=(_GPR["r11"],),
        plt_site_registers=(),
        toc_register=None,
        function_pointer_format=FunctionPointerFormat.PLAIN,
    ),
    os_abi="linux",
    syscall=SyscallABI(
        instructions=("syscall",),
        interrupt=None,
        number_register=_GPR["rax"],
        arg_registers=tuple(_GPR[n] for n in ("rdi", "rsi", "rdx", "r10", "r8", "r9")),
        stack_args=0,
        int64_pair_align=PairAlign.NONE,
        return_register=_GPR["rax"],
        return2_register=_GPR["rdx"],
        error_convention=SyscallErrorConvention.NEG_ERRNO_4095,
        clobbered=(_GPR["rcx"], _GPR["r11"]),
        number_base=0,
        numbers_family="x86_64",
    ),
    view_windowed_callinc=0,
    sources=Sources(
        ghidra_language="x86:LE:64:default",
        ghidra_compiler="gcc",
        ghidra_prototype="__stdcall",
        ghidra_join_klass=None,
        ghidra_keying=(),
        angr_simcc="angr.calling_conventions.SimCCSystemVAMD64",
        archinfo=None,
    ),
)


# ---------------------------------------------------------------------------
# X86_64/LITTLE:ms-x64 (Microsoft x64), derived from sysv for the tests of
# family lookup and the xmm6/ymm6 partial split.
# ---------------------------------------------------------------------------

assert X86_64_SYSV.fp_args is not None and X86_64_SYSV.sret is not None

X86_64_MS_X64 = dataclasses.replace(
    X86_64_SYSV,
    id="X86_64/LITTLE:ms-x64",
    variant="ms-x64",
    abi_id="ms-x64/ms-x64",
    family="ms-x64",
    abi=ABI.WINDOWS,
    is_default=False,
    is_family_default=True,
    toolchain="msvc",
    int_args=dataclasses.replace(
        X86_64_SYSV.int_args,
        registers=tuple(_GPR[n] for n in ("rcx", "rdx", "r8", "r9")),
        alloc=IntAlloc.FIRST_N,
        first_n_max_size=8,
    ),
    fp_args=dataclasses.replace(
        X86_64_SYSV.fp_args,
        registers=tuple(_XMM[:4]),
        index=FpIndex.POSITION,
        consumes_int_slot=True,
    ),
    stack=dataclasses.replace(
        X86_64_SYSV.stack, first_arg_offset=40, red_zone=0, shadow_space=32
    ),
    varargs=Varargs(
        policy=VarargsPolicy.FP_DUP_GPR,
        base_standard_scope=None,
        variadic_slot=None,
        signal=None,
        va_list=VaList(kind=VaListKind.POINTER, size=8, fields=()),
        fallback_record=None,
    ),
    returns=dataclasses.replace(
        X86_64_SYSV.returns,
        int_registers=(_GPR["rax"],),
        fp_registers=(_XMM[0],),
        small_struct_max=8,
        small_struct_sizes=(1, 2, 4, 8),
    ),
    sret=dataclasses.replace(X86_64_SYSV.sret, register=_GPR["rcx"]),
    preservation=_x86_64_partition(windows=True),
    # A PE image is entered by the loader, not through a SysV process stack.
    entry=EntryState(mode=(), registers=(), process=None),
    os_abi="windows",
    syscall=None,
    sources=dataclasses.replace(
        X86_64_SYSV.sources,
        ghidra_compiler="windows",
        ghidra_prototype="__fastcall",
        angr_simcc="angr.calling_conventions.SimCCMicrosoftAMD64",
    ),
)


# ---------------------------------------------------------------------------
# AARCH64/LITTLE:aapcs64 (AAPCS64; AArch64SysVCallingContext)
# ---------------------------------------------------------------------------

_X = {i: full(f"x{i}", 8, INT) for i in range(31)}
_Q = {i: full(f"q{i}", 16, VEC) for i in range(32)}
_SP = full("sp", 8, INT)


def _aarch64_partition() -> Preservation:
    entries: typing.List[typing.Tuple[PreservationKind, RegEntry]] = []
    roles: typing.Tuple[Role, ...]
    for i in range(31):
        if 19 <= i <= 28:
            entries.append((CALLEE, full(f"x{i}", 8, INT, Role.VALUE)))
        elif i == 29:
            entries.append(
                (CALLEE, full("x29", 8, INT, Role.VALUE, Role.FRAME_POINTER))
            )
        elif i in (16, 17):
            # AAPCS64 names x16/x17 IP0/IP1 and x18 PR.
            roles = (Role.LINKAGE_SCRATCH, Role.RESERVED)
            ip = (f"ip{i - 16}",)
            entries.append((CALLER, full(f"x{i}", 8, INT, *roles, aliases=ip)))
        elif i == 18:
            roles = (Role.PLATFORM_REGISTER, Role.RESERVED)
            entries.append((CALLER, full("x18", 8, INT, *roles, aliases=("pr",))))
        elif i == 30:
            entries.append((CALLER, full("x30", 8, INT, Role.LINK)))
        else:
            entries.append((CALLER, _X[i]))
    entries.append((CALLEE, full("sp", 8, INT, Role.STACK_POINTER)))
    entries.append((NEITHER, full("xzr", 8, INT, Role.RESERVED, Role.ZERO)))
    entries.append((CALLER, full("nzcv", 4, FLAGS, Role.CONDITION)))
    entries.append((CALLEE, full("fpcr", 8, SPECIAL, Role.FP_CONTROL)))
    entries.append((CALLER, full("fpsr", 8, SPECIAL)))
    entries.append((NEITHER, full("tpidr_el0", 8, SYSTEM, Role.TLS)))
    for i in range(32):
        if 8 <= i <= 15:
            # AAPCS64 6.1.2: only the low 64 bits (d8-d15) are preserved.
            entries.append((CALLEE, part(f"d{i}", f"q{i}", 8, 16, VEC, Role.FP_VALUE)))
            entries.append(
                (
                    CALLER,
                    part(
                        f"q{i}",
                        f"q{i}",
                        16,
                        16,
                        VEC,
                        offset=8,
                        abi_width=8,
                        abi_name=f"v{i}.d[1]",
                    ),
                )
            )
        else:
            entries.append((CALLER, _Q[i]))
    return partition(entries)


AARCH64_AAPCS64 = ABIDef(
    id="AARCH64/LITTLE:aapcs64",
    platform=AARCH64,
    variant="aapcs64",
    abi_id="aapcs64/aapcs64",
    family="aapcs64",
    abi=ABI.SYSTEMV,
    is_default=True,
    is_family_default=True,
    per_function=False,
    toolchain="gcc",
    confidence=Confidence.HIGH,
    int_args=IntArgSpec(
        registers=tuple(_X[i] for i in range(8)),
        pointer_registers=(),
        alloc=IntAlloc.SEQUENTIAL,
        gpr_width=8,
        first_n_max_size=0,
        pair_align=PairAlign.EVEN,
        split=Split.NEVER,
        close_on_fail=True,
        backfill_skipped=False,
        wide_on_stack=False,
        pair_order=PairOrder.MEMORY,
        ptr_one_reg=False,
    ),
    fp_args=FpArgSpec(
        registers=tuple(_Q[i] for i in range(8)),
        single_view=tuple(part(f"s{i}", f"q{i}", 4, 16, VEC) for i in range(8)),
        double_view=tuple(part(f"d{i}", f"q{i}", 8, 16, VEC) for i in range(8)),
        double_pairs=(),
        route=FpRoute.FPR,
        index=FpIndex.OWN,
        consumes_int_slot=False,
        exhaust=FpExhaust.STACK,
        file=FpFile.COUNTER,
        backfill=False,
        close_on_stack=True,
        flen=16,
        pair_order=PairOrder.MEMORY,
        stack_position=True,
    ),
    stack=StackSpec(
        alignment=16,
        entry_bias=0,
        first_arg_offset=0,
        slot_size=8,
        wide_align=16,
        natural=False,
        int_justify=Justify.LEFT,
        float_justify=Justify.LEFT,
        float_format=FloatEncoding.IEEE,
        red_zone=0,
        shadow_space=0,
        linkage_area=0,
        param_save_area=0,
        toc_save_slot=None,
        reserved_below_sp=0,
    ),
    varargs=Varargs(
        policy=VarargsPolicy.SAME,
        base_standard_scope=None,
        variadic_slot=None,
        signal=None,
        va_list=VaList(
            kind=VaListKind.STRUCT,
            size=32,
            fields=(
                VaListField("__stack", 0, 8),
                VaListField("__gr_top", 8, 8),
                VaListField("__vr_top", 16, 8),
                VaListField("__gr_offs", 24, 4),
                VaListField("__vr_offs", 28, 4),
            ),
        ),
        fallback_record=None,
    ),
    returns=ReturnSpec(
        int_registers=(_X[0], _X[1]),
        pointer_registers=(),
        pointer_mirror=(),
        fp_registers=tuple(_Q[i] for i in range(4)),
        fp_single=part("s0", "q0", 4, 16, VEC),
        fp_double=part("d0", "q0", 8, 16, VEC),
        int64_pair=(),
        int64_pair_order=PairOrder.MEMORY,
        fp_double_pairs=(),
        fp_pair_order=PairOrder.MEMORY,
        fp_encoding=FloatEncoding.IEEE,
        fp_named=(),
        small_struct_max=16,
        small_struct_sizes=None,
    ),
    sret=StructReturn(
        location=SretLocation.REGISTER,
        register=_X[8],
        arg_class=None,
        consumes_arg_slot=False,
        callee_pops=False,
        echo_register=None,
    ),
    extension=ExtensionRule(
        gpr_bits=64,
        int32_in_gpr=IntRepr.UNSPECIFIED,
        uint32_in_gpr=IntRepr.UNSPECIFIED,
        subint_promote_bits=0,
        subint_repr=IntRepr.UNSPECIFIED,
        bool_repr=IntRepr.UNSPECIFIED,
        pointer_repr=IntRepr.UNSPECIFIED,
        return_int32=IntRepr.UNSPECIFIED,
        stack_slot_repr=IntRepr.UNSPECIFIED,
        callee_relies=False,
        unknown_type_policy=UnknownTypePolicy.IDENTITY,
    ),
    preservation=_aarch64_partition(),
    special=SpecialRegisters(
        stack_pointer=_SP,
        frame_pointer=_X[29],
        frame_pointer_by_isa=(),
        global_pointer=None,
        gp_bias=0,
        tls=Tls(
            kind=TlsKind.BASE_REGISTER,
            register=full("tpidr_el0", 8, SYSTEM),
            descriptor_register=_X[0],
            variant=1,
            tp_offset=0,
            tcb_size=16,
            dtv_offset=0,
            get_addr_symbol="__tls_get_addr",
            get_addr_record=None,
        ),
        static_chain=None,
        pic_call_register=None,
    ),
    return_mechanics=ReturnMechanics(
        kind=ReturnKind.LINK_REGISTER,
        ra_register=_X[30],
        ra_stack_offset=None,
        ra_size=8,
        ra_mask=0xFFFFFFFFFFFFFFFF,
        delay_slot=False,
        callee_cleanup=False,
        thumb_bit=False,
        window_bits=0,
        exception_return_prefix=None,
        exception_frame=None,
    ),
    entry=EntryState(
        mode=(),
        registers=(),
        process=ProcessEntry(
            form=ProcessForm.SYSV_STACK,
            registers=(
                EntryReg(
                    register=_X[0],
                    value=EntryValue.ZERO,
                    symbol=None,
                    constant=None,
                    when=EntryCondition.ALWAYS,
                ),
            ),
            sp_points_at=StackPointerTarget.ARGC,
            sp_alignment=16,
        ),
    ),
    float_abi=FloatABI.HARD,
    fpu=FpuKind.FPU,
    data_model=lp64_data_model(False, FloatEncoding.BINARY128, False),
    linkage=Linkage(
        scratch=(_X[16], _X[17]),
        plt_site_registers=(),
        toc_register=None,
        function_pointer_format=FunctionPointerFormat.PLAIN,
    ),
    os_abi="linux",
    syscall=SyscallABI(
        instructions=("svc #0",),
        interrupt=None,
        number_register=_X[8],
        arg_registers=tuple(_X[i] for i in range(6)),
        stack_args=0,
        int64_pair_align=PairAlign.NONE,
        return_register=_X[0],
        return2_register=None,
        error_convention=SyscallErrorConvention.NEG_ERRNO_4095,
        clobbered=(),
        number_base=0,
        numbers_family="generic",
    ),
    view_windowed_callinc=0,
    sources=Sources(
        ghidra_language="AARCH64:LE:64:v8A",
        ghidra_compiler="default",
        ghidra_prototype="__cdecl",
        ghidra_join_klass=None,
        ghidra_keying=(),
        angr_simcc="angr.calling_conventions.SimCCAArch64",
        archinfo=None,
    ),
)


# ---------------------------------------------------------------------------
# TRICORE/LITTLE:eabi (TriCore EABI), for the tests of a separate address
# (pointer) register class. Only as much as those tests and validation need.
# ---------------------------------------------------------------------------

_TC_D = {i: full(f"d{i}", 4, INT) for i in range(16)}
_TC_A = {i: full(f"a{i}", 4, ADDRESS) for i in range(16)}


def _tricore_partition() -> Preservation:
    # A CALL saves the upper context (d8-d15, a10-a15, psw) and RET restores
    # it, so those are callee-saved; the lower context is caller-saved; a0,
    # a1, a8 and a9 are the system global registers.
    entries: typing.List[typing.Tuple[PreservationKind, RegEntry]] = []
    for i in range(16):
        if i >= 8:
            entries.append((CALLEE, full(f"d{i}", 4, INT, Role.VALUE)))
        else:
            entries.append((CALLER, _TC_D[i]))
    for i in range(16):
        if i in (0, 1):
            roles = (Role.GLOBAL_POINTER, Role.RESERVED)
            entries.append((NEITHER, full(f"a{i}", 4, ADDRESS, *roles)))
        elif i in (8, 9):
            entries.append((NEITHER, full(f"a{i}", 4, ADDRESS, Role.RESERVED)))
        elif i == 10:
            entries.append((CALLEE, full("a10", 4, ADDRESS, Role.STACK_POINTER)))
        elif i == 11:
            entries.append((CALLEE, full("a11", 4, ADDRESS, Role.LINK)))
        elif i == 14:
            roles = (Role.VALUE, Role.FRAME_POINTER)
            entries.append((CALLEE, full("a14", 4, ADDRESS, *roles)))
        elif i >= 12:
            entries.append((CALLEE, full(f"a{i}", 4, ADDRESS, Role.VALUE)))
        else:
            entries.append((CALLER, _TC_A[i]))
    entries.append((CALLEE, full("psw", 4, FLAGS, Role.CONDITION)))
    return partition(entries)


def _ilp32_data_model() -> DataModel:
    sizes = dict(
        char=1,
        short=2,
        int=4,
        long=4,
        long_long=8,
        pointer=4,
        size_t=4,
        ssize_t=4,
        ptrdiff_t=4,
        intmax_t=8,
        wchar_t=4,
        wint_t=4,
        float=4,
        double=8,
        long_double=8,
    )
    aligns = dict(sizes, long_long=4, intmax_t=4, double=4, long_double=4)
    return DataModel(
        name="ILP32",
        char_signed=True,
        sizes=CSizes(**sizes),
        aligns=CAligns(**aligns),
        long_double_format=FloatEncoding.IEEE,
        wchar_signed=True,
        max_align=8,
    )


TRICORE_EABI = dataclasses.replace(
    X86_64_SYSV,
    id="TRICORE/LITTLE:eabi",
    platform=TRICORE,
    variant="eabi",
    abi_id="tricore-eabi/eabi",
    family="tricore-eabi",
    confidence=Confidence.LOW,
    int_args=dataclasses.replace(
        X86_64_SYSV.int_args,
        registers=tuple(_TC_D[i] for i in range(4, 8)),
        pointer_registers=tuple(_TC_A[i] for i in range(4, 8)),
        alloc=IntAlloc.TYPED_CLASSES,
        gpr_width=4,
    ),
    fp_args=None,
    stack=dataclasses.replace(
        X86_64_SYSV.stack,
        alignment=8,
        entry_bias=0,
        first_arg_offset=0,
        slot_size=4,
        wide_align=8,
        red_zone=0,
    ),
    varargs=Varargs(
        policy=VarargsPolicy.SAME,
        base_standard_scope=None,
        variadic_slot=None,
        signal=None,
        va_list=VaList(kind=VaListKind.POINTER, size=4, fields=()),
        fallback_record=None,
    ),
    returns=dataclasses.replace(
        X86_64_SYSV.returns,
        int_registers=(_TC_D[2], _TC_D[3]),
        pointer_registers=(_TC_A[2],),
        fp_registers=(),
        fp_single=None,
        fp_double=None,
        fp_named=(),
        small_struct_max=8,
    ),
    sret=StructReturn(
        location=SretLocation.REGISTER,
        register=_TC_A[4],
        arg_class=ADDRESS,
        consumes_arg_slot=True,
        callee_pops=False,
        echo_register=None,
    ),
    extension=dataclasses.replace(X86_64_SYSV.extension, gpr_bits=32),
    preservation=_tricore_partition(),
    special=SpecialRegisters(
        stack_pointer=_TC_A[10],
        frame_pointer=_TC_A[14],
        frame_pointer_by_isa=(),
        global_pointer=_TC_A[0],
        gp_bias=0,
        tls=None,
        static_chain=None,
        pic_call_register=None,
    ),
    return_mechanics=ReturnMechanics(
        kind=ReturnKind.CONTEXT_RESTORE,
        ra_register=_TC_A[11],
        ra_stack_offset=None,
        ra_size=4,
        ra_mask=0xFFFFFFFF,
        delay_slot=False,
        callee_cleanup=False,
        thumb_bit=False,
        window_bits=0,
        exception_return_prefix=None,
        exception_frame=None,
    ),
    entry=EntryState(mode=(), registers=(), process=None),
    float_abi=FloatABI.SOFT,
    fpu=FpuKind.NONE,
    data_model=_ilp32_data_model(),
    linkage=Linkage(
        scratch=(),
        plt_site_registers=(),
        toc_register=None,
        function_pointer_format=FunctionPointerFormat.PLAIN,
    ),
    os_abi=None,
    syscall=None,
    sources=Sources(
        ghidra_language="tricore:LE:32:default",
        ghidra_compiler="default",
        ghidra_prototype=None,
        ghidra_join_klass=None,
        ghidra_keying=(),
        angr_simcc=None,
        archinfo=None,
    ),
)


RECORDS: typing.Tuple[ABIDef, ...] = (
    X86_64_SYSV,
    X86_64_MS_X64,
    AARCH64_AAPCS64,
    TRICORE_EABI,
)
