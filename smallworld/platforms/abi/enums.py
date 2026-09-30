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
    STACK_POINTER = "stack-pointer"

    FP_VALUE = "fp-value"
    """A callee-saved floating-point value (AArch64 ``d8``)."""

    FP_CONTROL = "fp-control"
    """Floating-point control state (x86 ``fctrl``, ``mxcsr`` control bits)."""

    CONDITION = "condition"
    VECTOR = "vector"
    TLS = "tls"
    TOC = "toc"
    GLOBAL_POINTER = "global-pointer"
    PLATFORM_REGISTER = "platform-register"
    LINK = "link"
    HW_CONTEXT = "hw-context"
    WINDOW = "window"
    RESERVED = "reserved"
    LINKAGE_SCRATCH = "linkage-scratch"
    ZERO = "zero"


class RegClass(_ValueEnum):
    """Register file a RegEntry belongs to."""

    INT = "int"
    ADDRESS = "address"
    """A separate address/pointer register file (TriCore ``a0..a15``)."""

    FP = "fp"
    VECTOR = "vector"
    FLAGS = "flags"
    SPECIAL = "special"
    SYSTEM = "system"


class PreservationKind(_ValueEnum):
    """The three disjoint classes of the preservation partition."""

    CALLEE_SAVED = "callee-saved"
    CALLER_SAVED = "caller-saved"
    NEITHER = "neither"


class Confidence(_ValueEnum):
    """How well a record is verified (probes, citations, oracles)."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IntAlloc(_ValueEnum):
    """Integer-argument allocation strategy."""

    SEQUENTIAL = "sequential"
    FIRST_N = "first-n"
    TYPED_CLASSES = "typed-classes"
    FIRST_FIT = "first-fit"
    DESCENDING = "descending"
    STACK_ONLY = "stack-only"


class PairAlign(_ValueEnum):
    """Alignment of a register pair holding a double-width value."""

    NONE = "none"
    EVEN = "even"


class Split(_ValueEnum):
    """Whether a multi-register value may be split between registers and stack."""

    NEVER = "never"
    LAST_REGISTER = "last-register"


class PairOrder(_ValueEnum):
    """Order of the halves of a value held in a register pair."""

    MEMORY = "memory"
    LOW_FIRST = "low-first"


class FpRoute(_ValueEnum):
    """Where floating-point arguments go."""

    STACK = "stack"
    INT = "int"
    FPR = "fpr"


class FpExhaust(_ValueEnum):
    """Where FP arguments go once the FP argument registers are exhausted."""

    STACK = "stack"
    INT = "int"


class FpIndex(_ValueEnum):
    """How the FP argument register for an argument is chosen."""

    OWN = "own"
    INT_CURSOR = "int-cursor"
    POSITION = "position"
    LEADING2 = "leading2"


class FpFile(_ValueEnum):
    """How FP argument registers are tracked while allocating."""

    COUNTER = "counter"
    ALIAS_BITMAP = "alias-bitmap"
    PAIR_COUNTER = "pair-counter"


class SignalKind(_ValueEnum):
    """What a variadic-call signal register carries."""

    VECTOR_COUNT = "vector-count"
    FPR_USED_FLAG = "fpr-used-flag"


class VarargsPolicy(_ValueEnum):
    """How variadic arguments are placed relative to named ones."""

    SAME = "same"
    FP_TO_INT = "fp-to-int"
    FP_TO_INT_AND_FPR = "fp-to-int-and-fpr"
    FP_DUP_GPR = "fp-dup-gpr"
    BASE_STANDARD = "base-standard"
    VARIADIC_STACK = "variadic-stack"
    LAST_NAMED_STACK = "last-named-stack"
    ALL_STACK = "all-stack"
    NONE = "none"
    FALLBACK = "fallback"


class FloatEncoding(_ValueEnum):
    """Encoding of a floating-point value in a register or slot."""

    IEEE = "ieee"
    F64_IN_FPR = "f64-in-fpr"
    NANBOX = "nanbox"
    X87_80 = "x87-80"
    M68K_80 = "m68k-80"
    M68K_96 = "m68k-96"
    IBM_DD = "ibm-dd"
    BINARY128 = "binary128"


class Justify(_ValueEnum):
    """Placement of a narrow value inside a wider stack slot."""

    LEFT = "left"
    RIGHT = "right"


class ReturnKind(_ValueEnum):
    """How a callee returns to its caller."""

    POP_RET = "pop-ret"
    LINK_REGISTER = "link-register"
    LINK_REGISTER_DELAY_SLOT = "link-register-delay-slot"
    WINDOWED_RETW = "windowed-retw"
    CONTEXT_RESTORE = "context-restore"


class TlsKind(_ValueEnum):
    """How the thread pointer is reached."""

    BASE_REGISTER = "base-register"
    GPR = "gpr"
    SEGMENT_SELECTOR = "segment-selector"
    COPROCESSOR = "coprocessor"
    HELPER_CALL = "helper-call"
    EMUTLS = "emutls"
    NONE = "none"


class FloatABI(_ValueEnum):
    """Floating-point calling convention family."""

    HARD = "hard"
    HARD_SINGLE = "hard-single"
    SOFT = "soft"
    SOFTFP = "softfp"
    X87 = "x87"
    CONFIG_DEPENDENT = "config-dependent"


class FpuKind(_ValueEnum):
    """The FPU the record assumes."""

    NONE = "none"
    VFP_D16 = "vfp-d16"
    VFP_D32 = "vfp-d32"
    X87_SSE = "x87-sse"
    FPU = "fpu"
    CONFIG_DEPENDENT = "config-dependent"


class IntRepr(_ValueEnum):
    """Representation of the unused upper bits of a narrow integer."""

    SIGN = "sign"
    ZERO = "zero"
    BY_TYPE = "by-type"
    UNSPECIFIED = "unspecified"


class ModeKind(_ValueEnum):
    """What an entry-state mode requirement does."""

    ENABLE = "enable"
    MODE = "mode"
    DEFAULT = "default"


class EntryValue(_ValueEnum):
    """The value an entry register must hold."""

    ENTRY_ADDRESS = "entry-address"
    TOC = "toc"
    GP_SYMBOL = "gp-symbol"
    SYMBOL = "symbol"
    DESCRIPTOR_WORD = "descriptor-word"
    ZERO = "zero"
    VECTOR_WORD = "vector-word"
    CONSTANT = "constant"


class FunctionPointerFormat(_ValueEnum):
    """What a C function pointer holds."""

    PLAIN = "plain"
    THUMB_BIT = "thumb-bit"
    DESCRIPTOR_24 = "descriptor-24"
    FDPIC = "fdpic"


class ProcessForm(_ValueEnum):
    """How a process (or a bare-metal image) is entered."""

    SYSV_STACK = "sysv-stack"
    RESET = "reset"


class SretLocation(_ValueEnum):
    """Where the hidden struct-return pointer is passed."""

    REGISTER = "register"
    STACK = "stack"


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
    STRUCT = "struct"


class EntryCondition(_ValueEnum):
    """When an entry-register requirement applies."""

    ALWAYS = "always"
    PIC = "pic"
    """Only in position-independent code."""

    GLOBAL_ENTRY = "global-entry"
    """Only when entering through the global entry point (ELFv2)."""


class UnknownTypePolicy(_ValueEnum):
    """How to canonicalize an integer whose C type is unknown."""

    IDENTITY = "identity"
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
