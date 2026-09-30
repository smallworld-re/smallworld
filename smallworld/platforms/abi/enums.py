"""Enumerations used by the ABI schema.

Every enum is a ``(str, enum.Enum)`` with lowercase kebab-case values, so a
member compares equal to its value (``Role.VALUE == "value"``). ``str()`` and
``format()`` (f-strings) also give the value, on every supported Python:
plain ``(str, enum.Enum)`` members format as ``"value"`` on 3.9 but as
``"Role.VALUE"`` from 3.11 (``str()`` already gives ``"Role.VALUE"`` on 3.9).
Declaration order is significant for :class:`Role`: a
:class:`~smallworld.platforms.abi.model.RegEntry`'s ``roles`` tuple is sorted
in that order, which keeps records deterministic (no ``frozenset`` iteration,
which depends on ``PYTHONHASHSEED``).
"""

import enum
import typing


class _ValueEnum(str, enum.Enum):
    """A ``(str, enum.Enum)`` whose ``str()`` and ``format()`` are its value."""

    def __str__(self) -> str:
        return self.value

    def __format__(self, format_spec: str) -> str:
        return format(self.value, format_spec)


class Role(_ValueEnum):
    """Why a register sits where it does in the preservation partition.

    Declaration order is the canonical sort order of ``RegEntry.roles``.
    """

    VALUE = "value"
    """Holds a callee-saved program value (x86-64 ``rbx``, AArch64 ``x19``)."""

    FRAME_POINTER = "frame-pointer"
    """The frame pointer (x86-64 ``rbp``, AArch64 ``x29``); also a value
    register."""

    STACK_POINTER = "stack-pointer"
    """The stack pointer."""

    FP_VALUE = "fp-value"
    """A callee-saved floating-point value (AArch64 ``d8``)."""

    FP_CONTROL = "fp-control"
    """Floating-point control state (x86 ``fctrl``, ``mxcsr`` control bits)."""

    CONDITION = "condition"
    """Condition-register fields or flags (PPC ``cr2..cr4``, x86
    ``rflags``)."""

    VECTOR = "vector"
    """Vector registers and vector state (AltiVec, ``VRSAVE``)."""

    TLS = "tls"
    """The thread pointer (x86-64 ``fsbase``, AArch64 ``tpidr_el0``, RISC-V
    ``tp``)."""

    TOC = "toc"
    """The TOC pointer, preserved as linkage state (PPC64 ``r2``)."""

    GLOBAL_POINTER = "global-pointer"
    """A small-data or GOT base preserved as linkage state (MIPS n64 ``gp``,
    PPC32 ``r13``, TriCore ``a0``/``a1``); never a value."""

    PLATFORM_REGISTER = "platform-register"
    """A register whose use the platform defines (ARM ``r9``, AArch64
    ``x18``)."""

    LINK = "link"
    """A return-address register that a source lists as preserved; never a
    value."""

    HW_CONTEXT = "hw-context"
    """Preserved by the hardware (the TriCore upper context, saved to a CSA on
    a call)."""

    WINDOW = "window"
    """Preserved by register-window rotation (Xtensa windowed)."""

    RESERVED = "reserved"
    """Reserved by the ABI for the toolchain or system. Combined with another
    class and role for dual-listed registers (AArch64 ``x16..x18`` on Linux,
    ARM ``r12``, MIPS ``at``)."""

    LINKAGE_SCRATCH = "linkage-scratch"
    """May be clobbered by PLT stubs and linker veneers between caller and
    callee (AArch64 ``x16``/``x17``, ARM ``r12``)."""

    ZERO = "zero"
    """A register hard-wired to zero (MIPS ``r0``, RISC-V ``x0``)."""


class RegClass(_ValueEnum):
    """Register file a RegEntry belongs to."""

    INT = "int"
    """General-purpose integer registers."""

    ADDRESS = "address"
    """A separate address/pointer register file (TriCore ``a0..a15``)."""

    FP = "fp"
    """Floating-point registers (x87 ``st0``, MIPS ``f0``)."""

    VECTOR = "vector"
    """Vector/SIMD registers (x86 ``ymm0``, AArch64 ``q0``)."""

    FLAGS = "flags"
    """Condition-flag registers (x86 ``rflags``)."""

    SPECIAL = "special"
    """Control and status registers (x87 ``fctrl`` and ``fstat``,
    ``mxcsr``)."""

    SYSTEM = "system"
    """System and thread-base registers (x86-64 ``fsbase``)."""


class PreservationKind(_ValueEnum):
    """The three disjoint classes of the preservation partition."""

    CALLEE_SAVED = "callee-saved"
    CALLER_SAVED = "caller-saved"
    NEITHER = "neither"


class Confidence(_ValueEnum):
    """How well a record is verified (probes, citations, oracles)."""

    HIGH = "high"
    """At least two agreeing sources, including the psABI or a compiler
    probe."""

    MEDIUM = "medium"
    """At least one agreeing source."""

    LOW = "low"
    """No ground truth to check against (for example Go, the TriCore stack
    model, big-endian Xtensa)."""


class IntAlloc(_ValueEnum):
    """Integer-argument allocation strategy."""

    SEQUENTIAL = "sequential"
    """Each argument takes the next free register of one list, then the stack
    (x86-64 SysV, AAPCS, RISC-V)."""

    FIRST_N = "first-n"
    """Only arguments of at most ``IntArgSpec.first_n_max_size`` bytes take
    registers, in order, until the registers run out; the rest go on the stack
    (MS i386 ``fastcall``/``thiscall``)."""

    TYPED_CLASSES = "typed-classes"
    """Pointers and data use two independent register sequences (TriCore EABI:
    ``a4..a7`` and ``d4..d7``)."""

    FIRST_FIT = "first-fit"
    """Each argument takes the first free register, or run of registers, that
    fits it, wherever it is (MSP430 EABI, ``R12..R15``)."""

    DESCENDING = "descending"
    """Registers are taken from the highest down (mspgcc legacy: ``R15`` to
    ``R12``)."""

    STACK_ONLY = "stack-only"
    """Every argument on the stack (i386 cdecl, m68k)."""


class PairAlign(_ValueEnum):
    """Alignment of a register pair holding a double-width value."""

    NONE = "none"
    """A pair may start at any register."""

    EVEN = "even"
    """A pair starts at an even index in the register list (ARM ``r0:r1`` or
    ``r2:r3``; PPC32 ``r3:r4``, as ``r3`` is index 0)."""


class Split(_ValueEnum):
    """Whether a multi-register value may be split between registers and stack."""

    NEVER = "never"
    """A value that does not fit in the remaining registers goes wholly on the
    stack."""

    LAST_REGISTER = "last-register"
    """A value may start in the last free register and continue on the stack
    (RISC-V, LoongArch)."""


class PairOrder(_ValueEnum):
    """Order of the halves of a value held in a register pair."""

    MEMORY = "memory"
    """The first register holds the half at the lower memory address: the most
    significant half on big-endian, the least significant on little-endian."""

    LOW_FIRST = "low-first"
    """The first register holds the least significant half on either byte order
    (MIPS o32 doubles in ``f0``, ``f1``)."""


class FpRoute(_ValueEnum):
    """Where floating-point arguments go."""

    STACK = "stack"
    """FP arguments go on the stack (i386, m68k)."""

    INT = "int"
    """FP arguments follow the integer convention (soft-float)."""

    FPR = "fpr"
    """FP arguments go in FP registers."""


class FpExhaust(_ValueEnum):
    """Where FP arguments go once the FP argument registers are exhausted."""

    STACK = "stack"
    """Then on the stack (x86-64 SysV, AArch64)."""

    INT = "int"
    """Then in free integer registers, then on the stack (RISC-V,
    LoongArch)."""


class FpIndex(_ValueEnum):
    """How the FP argument register for an argument is chosen."""

    OWN = "own"
    """A counter of its own over the FP registers (x86-64 SysV, AArch64)."""

    INT_CURSOR = "int-cursor"
    """The FP register with the index of the current integer argument slot (MS
    x64 ``xmm0..xmm3``; MIPS n64 ``f12+i``)."""

    POSITION = "position"
    """The FP register with the argument's position (vectorcall)."""

    LEADING2 = "leading2"
    """Only the first one or two arguments, when they lead the list and are FP,
    use FP registers (MIPS o32 ``f12``, ``f14``); the rest follow the integer
    convention."""


class FpFile(_ValueEnum):
    """How FP argument registers are tracked while allocating."""

    COUNTER = "counter"
    """One counter over the FP registers."""

    ALIAS_BITMAP = "alias-bitmap"
    """A bitmap over single-precision units, so a single may back-fill a gap a
    double left (AAPCS-VFP)."""

    PAIR_COUNTER = "pair-counter"
    """One counter over single-precision units, shared by singles and doubles,
    with doubles aligned to an even unit (SH ``fr4..fr11``)."""


class SignalKind(_ValueEnum):
    """What a variadic-call signal register carries."""

    VECTOR_COUNT = "vector-count"
    """An upper bound on the number of vector registers the call uses (x86-64
    ``al``)."""

    FPR_USED_FLAG = "fpr-used-flag"
    """A flag that is set when FP arguments are passed in FP registers (PPC32
    ``cr1``)."""


class VarargsPolicy(_ValueEnum):
    """How variadic arguments are placed relative to named ones."""

    SAME = "same"
    """Variadic arguments are placed like named ones (x86-64 SysV, AArch64
    Linux)."""

    FP_TO_INT = "fp-to-int"
    """Variadic FP arguments follow the integer convention (RISC-V, LoongArch,
    MIPS n64 and n32)."""

    FP_TO_INT_AND_FPR = "fp-to-int-and-fpr"
    """Variadic FP arguments go in both an FP register and the integer slot
    (PPC64 ELF)."""

    FP_DUP_GPR = "fp-dup-gpr"
    """Variadic FP arguments go in their FP register and are copied to the
    matching integer register (MS x64)."""

    BASE_STANDARD = "base-standard"
    """Calls to a variadic function use the base (soft-float) standard for the
    values ``base_standard_scope`` names (armhf, MIPS o32)."""

    VARIADIC_STACK = "variadic-stack"
    """Variadic arguments go on the stack (TriCore EABI)."""

    LAST_NAMED_STACK = "last-named-stack"
    """Variadic arguments and the last named argument go on the stack (MSP430
    EABI)."""

    ALL_STACK = "all-stack"
    """Every argument of a variadic function goes on the stack (GCC
    ``regparm``, Renesas SH)."""

    NONE = "none"
    """Variadic calls are not supported: placing one raises
    ``UnsupportedSignature`` (vectorcall, Go)."""

    FALLBACK = "fallback"
    """Variadic calls use the record named by ``Varargs.fallback_record`` (MS
    i386 ``fastcall`` and ``thiscall`` fall back to MS ``cdecl``)."""


class FloatEncoding(_ValueEnum):
    """Encoding of a floating-point value in a register or slot."""

    IEEE = "ieee"
    """IEEE 754 at the value's own width."""

    F64_IN_FPR = "f64-in-fpr"
    """A single-precision value held in an FP register as a double (PPC)."""

    NANBOX = "nanbox"
    """A narrower value NaN-boxed in a wider FP register: the upper bits all
    ones (RISC-V)."""

    X87_80 = "x87-80"
    """The x87 80-bit extended format."""

    M68K_80 = "m68k-80"
    """The m68k 80-bit extended format, as held in an FP register."""

    M68K_96 = "m68k-96"
    """The m68k 96-bit extended format, as stored in memory."""

    IBM_DD = "ibm-dd"
    """IBM double-double (PPC ``long double``)."""

    BINARY128 = "binary128"
    """IEEE 754 binary128 (AArch64 Linux ``long double``)."""


class Justify(_ValueEnum):
    """Placement of a narrow value inside a wider stack slot."""

    LEFT = "left"
    """In the lowest-addressed bytes of the slot."""

    RIGHT = "right"
    """In the highest-addressed bytes of the slot, where a big-endian value
    widened to the slot would keep them."""


class ReturnKind(_ValueEnum):
    """How a callee returns to its caller."""

    POP_RET = "pop-ret"
    """The return address is on the stack and the return instruction pops it
    (x86, m68k, MSP430)."""

    LINK_REGISTER = "link-register"
    """A branch to the address in a link register (AArch64 ``x30``, ARM
    ``lr``)."""

    LINK_REGISTER_DELAY_SLOT = "link-register-delay-slot"
    """A branch to a link register, with a delay slot (MIPS ``jr $ra``, SH
    ``rts``)."""

    WINDOWED_RETW = "windowed-retw"
    """Xtensa windowed ``retw``: the return address and window increment are in
    ``a0``, and the register window rotates back."""

    CONTEXT_RESTORE = "context-restore"
    """TriCore ``ret``: ``pc`` comes from ``a11``, then the upper context is
    restored from the CSA."""


class TlsKind(_ValueEnum):
    """How the thread pointer is reached."""

    BASE_REGISTER = "base-register"
    """A thread-pointer base register (x86-64 ``fsbase``, AArch64
    ``tpidr_el0``)."""

    GPR = "gpr"
    """A general-purpose register reserved as the thread pointer (PPC
    ``r2``/``r13``, RISC-V and LoongArch ``tp``)."""

    SEGMENT_SELECTOR = "segment-selector"
    """A segment selector and its GDT descriptor (i386 ``gs``), with no base
    register."""

    COPROCESSOR = "coprocessor"
    """A coprocessor or system register read by an instruction (ARM TPIDRURO;
    MIPS UserLocal via ``rdhwr``)."""

    HELPER_CALL = "helper-call"
    """A helper function or system call returns the thread pointer (m68k
    ``__m68k_read_tp``)."""

    EMUTLS = "emutls"
    """Compiler-emulated TLS (``__emutls_get_address``). Reserved; no record
    uses it yet."""

    NONE = "none"
    """No TLS convention (bare metal)."""


class FloatABI(_ValueEnum):
    """Floating-point calling convention family."""

    HARD = "hard"
    """FP values are passed and returned in FP or vector registers."""

    HARD_SINGLE = "hard-single"
    """Only single precision uses FP registers; doubles follow the integer
    convention (RISC-V lp64f)."""

    SOFT = "soft"
    """FP values follow the integer convention."""

    SOFTFP = "softfp"
    """FP values follow the integer convention, but the code may use FP
    instructions (ARM ``-mfloat-abi=softfp``)."""

    X87 = "x87"
    """FP arguments on the stack, FP results in x87 ``st0`` (i386)."""

    CONFIG_DEPENDENT = "config-dependent"
    """The variant exists in both hard- and soft-float forms, and no binary
    marker tells them apart."""


class FpuKind(_ValueEnum):
    """The FPU the record assumes."""

    NONE = "none"
    """No FPU."""

    VFP_D16 = "vfp-d16"
    """ARM VFP with 16 double-precision registers."""

    VFP_D32 = "vfp-d32"
    """ARM VFP with 32 double-precision registers."""

    X87_SSE = "x87-sse"
    """x87 plus SSE."""

    FPU = "fpu"
    """The architecture's FPU, with no finer distinction recorded."""

    CONFIG_DEPENDENT = "config-dependent"
    """Depends on how the toolchain was configured."""


class IntRepr(_ValueEnum):
    """Representation of the unused upper bits of a narrow integer."""

    SIGN = "sign"
    """Sign-extended."""

    ZERO = "zero"
    """Zero-extended."""

    BY_TYPE = "by-type"
    """Sign-extended for signed types, zero-extended for unsigned ones."""

    UNSPECIFIED = "unspecified"
    """The upper bits are undefined: a reader must ignore them, and a writer
    need not set them."""


class ModeKind(_ValueEnum):
    """What an entry-state mode requirement does."""

    ENABLE = "enable"
    """Bits that enable a unit (ARM FPEXC.EN, PPC MSR[FP], MIPS CU1). Skipped
    on backends that do not gate FP."""

    MODE = "mode"
    """Bits that select an operating mode (MIPS FR, M-profile Thread/MSP)."""

    DEFAULT = "default"
    """A documented default value (x86 MXCSR ``0x1F80``, x87 control word
    ``0x037F``)."""


class EntryValue(_ValueEnum):
    """The value an entry register must hold."""

    ENTRY_ADDRESS = "entry-address"
    """The address of the function being entered (MIPS PIC ``t9``; ELFv2
    ``r12``)."""

    TOC = "toc"
    """The TOC pointer, ``.TOC.`` (ELFv2 ``r2`` at the local entry point)."""

    GP_SYMBOL = "gp-symbol"
    """The address of the symbol that defines the global pointer, named by
    ``EntryReg.symbol`` (RISC-V ``gp``: ``__global_pointer$``)."""

    SYMBOL = "symbol"
    """The address of the symbol named by ``EntryReg.symbol``."""

    DESCRIPTOR_WORD = "descriptor-word"
    """A word of the function descriptor (ELFv1 ``r2``: word 1, the TOC)."""

    ZERO = "zero"
    """Zero (x86-64 process-entry ``rdx``)."""

    VECTOR_WORD = "vector-word"
    """A word of the vector table (M-profile reset: ``sp`` from word 0, ``pc``
    from word 1)."""

    CONSTANT = "constant"
    """The value in ``EntryReg.constant``."""


class FunctionPointerFormat(_ValueEnum):
    """What a C function pointer holds."""

    PLAIN = "plain"
    """The code address."""

    THUMB_BIT = "thumb-bit"
    """The code address, with bit 0 set for a Thumb target (ARM)."""

    DESCRIPTOR_24 = "descriptor-24"
    """The address of a 24-byte function descriptor ``{entry, TOC,
    environment}`` (PPC64 ELFv1)."""

    FDPIC = "fdpic"
    """The address of an FDPIC function descriptor (entry address and GOT
    pointer)."""


class ProcessForm(_ValueEnum):
    """How a process (or a bare-metal image) is entered."""

    SYSV_STACK = "sysv-stack"
    """The System V process start: ``argc``, ``argv``, ``envp`` and ``auxv`` on
    the stack."""

    RESET = "reset"
    """A bare-metal reset: ``sp`` and ``pc`` come from the vector table
    (M-profile)."""


class SretLocation(_ValueEnum):
    """Where the hidden struct-return pointer is passed."""

    REGISTER = "register"
    """In a register (x86-64 SysV ``rdi``, AArch64 ``x8``)."""

    STACK = "stack"
    """On the stack, as a hidden first argument (i386 SysV)."""


class SyscallErrorConvention(_ValueEnum):
    """How a system call reports failure."""

    NEG_ERRNO_4095 = "neg-errno-4095"
    """A return value in ``[-4095, -1]`` is ``-errno`` (most Linux ports)."""

    MIPS_A3_FLAG = "mips-a3-flag"
    """``a3`` is nonzero on failure and ``v0`` holds the positive errno."""

    PPC_CR0_SO = "ppc-cr0-so"
    """``CR0.SO`` is set on failure and ``r3`` holds the positive errno."""


class VaListKind(_ValueEnum):
    """The C type of ``va_list``."""

    POINTER = "pointer"
    """A pointer into the argument area."""

    STRUCT = "struct"
    """A structure (x86-64 SysV, 24 bytes)."""


class EntryCondition(_ValueEnum):
    """When an entry-register requirement applies."""

    ALWAYS = "always"
    """In every call."""

    PIC = "pic"
    """Only in position-independent code."""

    GLOBAL_ENTRY = "global-entry"
    """Only when entering through the global entry point (ELFv2)."""


class UnknownTypePolicy(_ValueEnum):
    """How to canonicalize an integer whose C type is unknown."""

    IDENTITY = "identity"
    """Leave the value unchanged (x86-64 SysV)."""

    SEXT32 = "sext32"
    """Sign-extend from 32 bits (MIPS64, RISC-V 64, LoongArch64)."""

    BY_TYPE = "by-type"
    """Sign- or zero-extend as a selector chooses."""


class StackPointerTarget(_ValueEnum):
    """What the stack pointer points at when a process (or image) starts."""

    ARGC = "argc"
    """The System V process stack: ``argc``, then ``argv`` and ``envp``."""

    STACK_TOP = "stack-top"
    """The initial stack top, with nothing on it (M-profile reset)."""


#: Name forms accepted by the query methods (``form=``).
NAME_FORMS: typing.Tuple[str, ...] = ("root", "name", "abi")


__all__ = [
    "Confidence",
    "EntryCondition",
    "EntryValue",
    "FloatABI",
    "FloatEncoding",
    "FpExhaust",
    "FpFile",
    "FpIndex",
    "FpRoute",
    "FpuKind",
    "FunctionPointerFormat",
    "IntAlloc",
    "IntRepr",
    "Justify",
    "ModeKind",
    "NAME_FORMS",
    "PairAlign",
    "PairOrder",
    "PreservationKind",
    "ProcessForm",
    "RegClass",
    "ReturnKind",
    "Role",
    "SignalKind",
    "Split",
    "SretLocation",
    "StackPointerTarget",
    "SyscallErrorConvention",
    "TlsKind",
    "UnknownTypePolicy",
    "VaListKind",
    "VarargsPolicy",
]
