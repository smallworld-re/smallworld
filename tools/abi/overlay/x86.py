"""Overlay for the x86 family: the register file and ``X86_64/LITTLE:sysv``.

Fields the dependencies are authoritative for (overlay/authority.py) are not
listed here; everything else is, each with its citation. Values that rest
only on the research master dataset carry ``Cite.master_seed`` and are
capped at medium confidence until someone re-verifies them.
"""

import re
import typing

from .documents import GLIBC_TAG, MAN_PAGES
from .documents import amd64_psabi as psabi
from .schema import (
    AngrJoin,
    Cite,
    Deviation,
    Expect,
    GhidraJoin,
    Hand,
    OracleAck,
    RecordSpec,
    RegisterFile,
)

SYSV = "X86_64/LITTLE:sysv"


def seed(field: str, hint: str = "") -> Cite:
    return Cite.master_seed(SYSV, field, hint)


def hands(
    prefix: str,
    values: typing.Mapping[str, typing.Any],
    *cite: Cite,
    confidence: str = "high",
    note: str = "",
) -> typing.Dict[str, Hand]:
    """One Hand per ``prefix.key``, all with the same citations."""
    dot = prefix + "." if prefix else ""
    return {
        dot + key: Hand(value, tuple(cite), confidence, note)
        for key, value in values.items()
    }


REGISTERS = psabi("§3.2.1 (Registers), Figure 3.4 (Register Usage)")
STACK_FRAME = psabi("§3.2.2 (The Stack Frame)")
PASSING = psabi("§3.2.3 (Parameter Passing)")
RETURNING = psabi("§3.2.3 (Parameter Passing: Returning of Values)")
SCALARS = psabi("§3.1.2 (Data Representation), Figure 3.1 (Scalar Types)")
PROCESS = psabi("§3.4.1 (Initial Stack and Register State)")
VARARGS = psabi("§3.5.7 (Variable Argument Lists)")
LINUX_SYSCALL = psabi("§A.2.1 (Linux Kernel Conventions: Calling Conventions)")

# ---------------------------------------------------------------------------
# The x86-64 register file
# ---------------------------------------------------------------------------

_GPRS = "rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15".split()
_PERCENT = re.compile(
    r"(r[a-d]x|r[sd]i|r[sb]p|r\d+[dwb]?|e[a-d]x|e[sd]i|e[sb]p|[a-d][lh]|[xyz]mm\d+)"
)
_X87 = re.compile(r"st(\d)")


def _x86_64_abi_name(name: str) -> str:
    """AT&T spelling: ``%rdi``, ``%xmm0``, ``%st(0)``; control, flag and
    segment-base registers keep smallworld's name."""
    x87 = _X87.fullmatch(name)
    if x87:
        return f"%st({x87.group(1)})"
    return "%" + name if _PERCENT.fullmatch(name) else name


X86_64_REGISTER_FILE = RegisterFile(
    name="x86-64",
    roots=tuple(_GPRS)
    + ("rflags",)
    + tuple(f"fpr{i}" for i in range(8))
    + ("fctrl", "fstat", "fsbase")
    + tuple(f"ymm{i}" for i in range(16)),
    classes={
        **{r: "int" for r in _GPRS},
        "rflags": "flags",
        **{f"fpr{i}": "fp" for i in range(8)},
        "fctrl": "special",
        "fstat": "special",
        "fsbase": "system",
        **{f"ymm{i}": "vector" for i in range(16)},
        "mxcsr": "special",
        "st0": "fp",
    },
    unmodeled={"mxcsr": 4, "st0": 10},
    unmodeled_roots=("mxcsr",),
    roles={"rflags": ("condition",)},
    callee_roles={"fctrl": ("fp-control",), "mxcsr": ("fp-control",)},
    # MXCSR bits 0-15 are defined (flags 0-5, DAZ 6, masks 7-12, RC 13-14,
    # FZ 15); bits 16-31 are reserved, so the generator puts them in neither.
    defined_masks={"mxcsr": 0xFFFF},
    abi_name=_x86_64_abi_name,
    cite=(
        REGISTERS,
        psabi("§3.2.1 (Registers): the MXCSR control bits and the x87 control word"),
    ),
)

# ---------------------------------------------------------------------------
# X86_64/LITTLE:sysv
# ---------------------------------------------------------------------------

_GHIDRA_CSPEC = "x86/data/languages/x86-64-gcc.cspec"

_HAND: typing.Dict[str, Hand] = {}

# identity
_HAND.update(
    hands(
        "",
        {
            "abi_id": "amd64-psabi/sysv",
            "family": "amd64-psabi",
            "abi": "system-v",
            "is_default": True,
            "is_family_default": True,
            "per_function": False,
            "os_abi": "linux",
        },
        psabi("§1 (Introduction)"),
        LINUX_SYSCALL,
    )
)
_HAND.update(
    hands(
        "",
        {"toolchain": "gcc"},
        seed("variant_meta", "x86_64-linux-gnu GCC is the test toolchain"),
    )
)
# The record's own claim; stage 2 lowers it to its least verified entry
# (medium while any master-seed marker remains).
_HAND["confidence"] = Hand("high", (PASSING, REGISTERS))
_HAND["view_windowed_callinc"] = Hand(0, (REGISTERS,), note="no register windows")

# integer arguments (the registers come from Ghidra)
_HAND.update(
    hands(
        "int_args",
        {
            "pointer_registers": (),
            "alloc": "sequential",
            "gpr_width": 8,
            "first_n_max_size": 0,
            "pair_align": "none",
            "split": "never",
            "close_on_fail": False,
            "backfill_skipped": False,
            "wide_on_stack": False,
            "pair_order": "memory",
            "ptr_one_reg": False,
        },
        PASSING,
    )
)

# FP arguments (the registers come from Ghidra)
_HAND.update(
    hands(
        "fp_args",
        {
            "single_view": (),
            "double_view": (),
            "double_pairs": (),
            "route": "fpr",
            "index": "own",
            "consumes_int_slot": False,
            "exhaust": "stack",
            "file": "counter",
            "backfill": False,
            "close_on_stack": False,
            "flen": 8,
            "pair_order": "memory",
            "stack_position": True,
        },
        PASSING,
    )
)

# stack (first offset and slot size come from Ghidra)
_HAND.update(
    hands(
        "stack",
        {
            "alignment": 16,
            "entry_bias": 8,
            "red_zone": 128,
            "shadow_space": 0,
            "linkage_area": 0,
            "param_save_area": 0,
            "toc_save_slot": None,
            "reserved_below_sp": 0,
        },
        STACK_FRAME,
    )
)
_HAND.update(
    hands(
        "stack",
        {
            "wide_align": 16,
            "natural": False,
            "int_justify": "left",
            "float_justify": "left",
            "float_format": "ieee",
        },
        PASSING,
        SCALARS,
    )
)

# varargs
_HAND.update(
    hands(
        "varargs",
        {
            "policy": "same",
            "base_standard_scope": None,
            "variadic_slot": None,
            "signal": {"kind": "vector-count", "register": "al", "mask": 0xFF},
            "fallback_record": None,
        },
        PASSING,
    )
)
_HAND["varargs.va_list"] = Hand(
    {
        "kind": "struct",
        "size": 24,
        "fields": (
            ("gp_offset", 0, 4),
            ("fp_offset", 4, 4),
            ("overflow_arg_area", 8, 8),
            ("reg_save_area", 16, 8),
        ),
    },
    (VARARGS,),
)

# returns (int and FP registers come from Ghidra)
_HAND.update(
    hands(
        "returns",
        {
            "pointer_registers": (),
            "pointer_mirror": (),
            "fp_single": "xmm0",
            "fp_double": "xmm0",
            "int64_pair": (),
            "int64_pair_order": "memory",
            "fp_double_pairs": (),
            "fp_pair_order": "memory",
            "fp_encoding": "ieee",
            "fp_named": (("x87-80", "st0"),),
            "small_struct_max": 16,
            "small_struct_sizes": None,
        },
        RETURNING,
    )
)

# struct return (the register comes from Ghidra)
_HAND.update(
    hands(
        "sret",
        {
            "location": "register",
            "arg_class": "int",
            "consumes_arg_slot": True,
            "callee_pops": False,
            "echo_register": "rax",
        },
        RETURNING,
    )
)

# extension of narrow integers
_HAND.update(
    hands(
        "extension",
        {
            "gpr_bits": 64,
            "int32_in_gpr": "unspecified",
            "uint32_in_gpr": "unspecified",
            "pointer_repr": "unspecified",
            "return_int32": "unspecified",
            "stack_slot_repr": "unspecified",
        },
        PASSING,
    )
)
_HAND["extension.bool_repr"] = Hand(
    "zero",
    (psabi("§3.2.3 (Parameter Passing), the footnote on _Bool"),),
    confidence="medium",
    note=(
        "the psABI guarantees only that bits 1-7 of a _Bool are zero; bits 8 "
        "and up are unspecified, and gcc and clang callers zero-extend to 32 "
        "bits, so 'zero' holds for the low byte only"
    ),
)
_HAND.update(
    hands(
        "extension",
        {
            "subint_promote_bits": 32,
            "subint_repr": "by-type",
            "callee_relies": True,
            "unknown_type_policy": "identity",
        },
        seed(
            "arg_extension",
            "gcc and clang callers extend char/short to 32 bits; clang callees "
            "rely on it",
        ),
    )
)

# preservation (callee-saved comes from Ghidra; caller-saved is derived)
_HAND["preservation.neither"] = Hand(
    ("fsbase",), (REGISTERS,), note="the thread pointer (%fs base)"
)

# special registers (the stack pointer comes from Ghidra; TLS offsets and
# variant from archinfo)
_HAND.update(
    hands(
        "special",
        {
            "frame_pointer": "rbp",
            "frame_pointer_by_isa": (),
            "global_pointer": None,
            "gp_bias": 0,
            "static_chain": "r10",
            "pic_call_register": None,
        },
        REGISTERS,
    )
)
_HAND.update(
    hands(
        "special.tls",
        {"kind": "base-register", "register": "fsbase"},
        REGISTERS,
    )
)
_HAND.update(
    hands(
        "special.tls",
        {
            "descriptor_register": "rax",
            "get_addr_symbol": "__tls_get_addr",
            "get_addr_record": None,
        },
        seed("special.tls", "TLS variant II; TLSDESC argument in %rax"),
    )
)
# Tls.tcb_size is the size of the thread control block that sits between the
# thread pointer and the first TLS block in TLS variant I (AArch64: 16), and
# so enters every TLS offset there. x86-64 uses variant II: the TCB is at the
# thread pointer and the TLS blocks lie below it (glibc TLS_TCB_AT_TP), so no
# TCB size enters an offset and the value is 0. archinfo's tcbhead_size (704)
# is a different quantity, glibc's allocation for the TCB and thread
# descriptor, so it is not taken.
_HAND["special.tls.tcb_size"] = Hand(
    0, (Cite.glibc("sysdeps/x86_64/nptl/tls.h:114-115", GLIBC_TAG),)
)

# return mechanics (the return address location comes from angr)
_HAND.update(
    hands(
        "return_mechanics",
        {
            "kind": "pop-ret",
            "ra_mask": 0xFFFFFFFFFFFFFFFF,
            "delay_slot": False,
            "callee_cleanup": False,
            "thumb_bit": False,
            "window_bits": 0,
            "exception_return_prefix": None,
            "exception_frame": None,
        },
        STACK_FRAME,
    )
)

# entry state
_HAND.update(hands("entry", {"mode": (), "registers": ()}, PROCESS))
_HAND["entry.process"] = Hand(
    {
        "form": "sysv-stack",
        "registers": (
            {
                "register": "rdx",
                "value": "zero",
                "symbol": None,
                "constant": None,
                "when": "always",
            },
        ),
        "sp_points_at": "argc",
        "sp_alignment": 16,
    },
    (seed("entry_state", "rdx holds the atexit function; 0 from the kernel"),),
    note="archinfo's entry_register_values describe the loader, not the kernel",
)

# float ABI and FPU
_HAND.update(
    hands(
        "",
        {"float_abi": "hard", "fpu": "x87-sse"},
        PASSING,
        psabi("§3.1.1 (Processor Architecture)"),
    )
)

# data model
_SIZES = {
    "char": 1,
    "short": 2,
    "int": 4,
    "long": 8,
    "long_long": 8,
    "pointer": 8,
    "float": 4,
    "double": 8,
    "long_double": 16,
}
_TYPEDEFS = {
    "size_t": 8,
    "ssize_t": 8,
    "ptrdiff_t": 8,
    "intmax_t": 8,
    "wchar_t": 4,
    "wint_t": 4,
}
_HAND.update(
    hands(
        "data_model",
        {
            "name": "LP64",
            "char_signed": True,
            "long_double_format": "x87-80",
            "max_align": 16,
        },
        SCALARS,
    )
)
_HAND.update(hands("data_model.sizes", _SIZES, SCALARS))
_HAND.update(hands("data_model.aligns", _SIZES, SCALARS))
_TYPEDEF_SEED = seed("data_model", "glibc x86_64 typedefs; wchar_t is int")
_HAND.update(hands("data_model.sizes", _TYPEDEFS, _TYPEDEF_SEED))
_HAND.update(hands("data_model.aligns", _TYPEDEFS, _TYPEDEF_SEED))
_HAND["data_model.wchar_signed"] = Hand(True, (_TYPEDEF_SEED,))

# dynamic linking
_HAND.update(
    hands(
        "linkage",
        {
            "plt_site_registers": (),
            "toc_register": None,
            "function_pointer_format": "plain",
        },
        REGISTERS,
    )
)
_HAND["linkage.scratch"] = Hand(
    ("r11",), (seed("extensions", "r11 is the PLT scratch register"),)
)

# Linux system calls (number and return registers come from angr)
_HAND.update(
    hands(
        "syscall",
        {
            "instructions": ("syscall",),
            "interrupt": None,
            "arg_registers": ("rdi", "rsi", "rdx", "r10", "r8", "r9"),
            "stack_args": 0,
            "int64_pair_align": "none",
            "error_convention": "neg-errno-4095",
            "clobbered": ("rcx", "r11"),
            "number_base": 0,
        },
        LINUX_SYSCALL,
    )
)
_HAND["syscall.return2_register"] = Hand(
    "rdx",
    (Cite.manpage("syscall(2), Architecture calling conventions", MAN_PAGES),),
    note=(
        "syscall(2) lists rdx as x86-64's second return register (retval2); "
        "the x86-64 kernel itself never writes it, so no x86-64 system call "
        "returns a value there"
    ),
)
_HAND["syscall.numbers_family"] = Hand("x86_64", (seed("syscall"),))

X86_64_SYSV = RecordSpec(
    id=SYSV,
    architecture="X86_64",
    byteorder="LITTLE",
    variant="sysv",
    ghidra=GhidraJoin("x86:LE:64:default", "gcc", "__stdcall"),
    angr=AngrJoin("ArchAMD64", "LE", "Linux"),
    register_file=X86_64_REGISTER_FILE,
    feature="x86-64-sysv",
    hand=_HAND,
    expectations=(
        # Fields only one dependency provides, checked against the documents.
        Expect("sret.register", "rdi", (RETURNING,)),
        Expect("stack.slot_size", 8, (PASSING,)),
        Expect("return_mechanics.ra_stack_offset", 0, (STACK_FRAME,)),
        Expect("return_mechanics.ra_size", 8, (STACK_FRAME,)),
        Expect("syscall.number_register", "rax", (LINUX_SYSCALL,)),
        Expect("syscall.return_register", "rax", (LINUX_SYSCALL,)),
        Expect(
            "special.tls.variant",
            2,
            (Cite.glibc("sysdeps/x86_64/nptl/tls.h:114-115", GLIBC_TAG),),
        ),
        Expect(
            "special.tls.tp_offset",
            0,
            (Cite.glibc("sysdeps/x86_64/nptl/tls.h:42-47", GLIBC_TAG),),
        ),
        Expect(
            "special.tls.dtv_offset",
            8,
            (Cite.glibc("sysdeps/x86_64/nptl/tls.h:42-47", GLIBC_TAG),),
        ),
    ),
    deviations=(
        Deviation(
            id="KD-GH-X86-64-FP-CONTROL",
            record=SYSV,
            field="preservation.callee_saved",
            dependency="ghidra",
            observed={
                version: ("rbx", "r12", "r13", "r14", "r15", "rsp", "rbp")
                for version in ("12.1", "11.4.2")
            },
            abi_value=(
                "rbx",
                "r12",
                "r13",
                "r14",
                "r15",
                "rsp",
                "rbp",
                "fctrl",
                "mxcsr&0xFFC0",
            ),
            klass="b",
            root_cause="GH-UNAFFECTED-CONTROL-STATE",
            cite=(
                psabi(
                    "§3.2.1 (Registers): the control bits of the MXCSR register "
                    "and the x87 control word are callee-saved"
                ),
                Cite.ghidra("12.1", _GHIDRA_CSPEC + ":119-127"),
                Cite.ghidra("11.4.2", _GHIDRA_CSPEC + ":119-127"),
            ),
        ),
    ),
    oracle_acks=(
        # Ghidra's long_double_size is the 10-byte x87 value; the cspec notes
        # aligned-length=16, which is sizeof(long double).
        OracleAck(
            id="ACK-GH-X86-64-LONG-DOUBLE-SIZE",
            dependency="ghidra",
            root_cause="GH-LONG-DOUBLE-VALUE-SIZE",
            field_pattern=SYSV + ":data_model.sizes.long_double",
            oracle=10,
            final=16,
            cite=(
                SCALARS,
                Cite.ghidra("12.1", _GHIDRA_CSPEC + ":16"),
                Cite.ghidra("11.4.2", _GHIDRA_CSPEC + ":16"),
            ),
        ),
    ),
)
