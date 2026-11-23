import abc
import enum
import typing
from dataclasses import dataclass

from ... import utils
from ..platforms import Architecture, Byteorder, Platform


@dataclass(frozen=True)
class RegisterDef:
    name: str
    size: int


@dataclass(frozen=True)
class RegisterAliasDef(RegisterDef):
    parent: str
    offset: int


class IsaBit(enum.Enum):
    """What bit 0 of a code address means on a platform.

    Some CPUs run two instruction sets and take the one to run from bit 0 of
    a jump target (ARM's Thumb bit, MIPS's ISA bit). On those, code
    addresses in an ELF image and in registers such as the return address
    carry that bit; the instruction itself is at the even address.
    """

    NONE = "none"
    """Bit 0 is part of the address."""

    SELECTS = "selects"
    """Bit 0 selects the instruction set: 1 the alternate one (Thumb,
    microMIPS), 0 the standard one."""

    REQUIRED = "required"
    """The CPU runs only the alternate instruction set, and bit 0 must be 1
    (ARMv6-M and ARMv7-M Thumb)."""


class PlatformDef(metaclass=abc.ABCMeta):
    #: What bit 0 of a code address means; see :class:`IsaBit`. Where it
    #: selects the instruction set, :meth:`.Emulator.get_isa_mode` and
    #: :meth:`.Emulator.set_isa_mode` read and set the current one.
    isa_bit: IsaBit = IsaBit.NONE

    #: Where the CPU keeps its instruction-set mode, as (register, bit), for
    #: a platform whose isa_bit is SELECTS and whose mode is an architectural
    #: register bit (ARM: cpsr's T bit). None means the ``isa_mode``
    #: pseudo-register, which machine definitions map to wherever their
    #: engine keeps the mode (microMIPS).
    isa_mode_register: typing.Optional[typing.Tuple[str, int]] = None

    #: Ghidra/SLEIGH language id (arch+byteorder) -- the single source of
    #: truth for both the Ghidra emulator's machine defs and the pcode
    #: analysis. None if this platform has no Ghidra language.
    ghidra_language_id: typing.Optional[str] = None

    #: Context field values to decode this platform's code with, where its
    #: SLEIGH language holds several encodings and the default is not this
    #: platform's (microMIPS: ISA_MODE). The single source for both the Ghidra
    #: emulator's machine defs and the p-code use/def analysis, which, like
    #: ghidra_register_aliases below, cannot reach the machine defs. Empty
    #: where the language's defaults are right.
    ghidra_context: typing.Dict[str, int] = {}

    #: Mnemonics whose decoding records, in the SLEIGH context, how later code
    #: decodes. MIPS's jalx says its target, and everything above it, is in
    #: the other encoding. The p-code use/def analysis drops a cached context
    #: after decoding one. Empty where no instruction does this.
    ghidra_context_writing_mnemonics: typing.FrozenSet[str] = frozenset()

    #: Ghidra/SLEIGH register name -> the name THIS platform uses for the
    #: same physical register, for the cases where the two namespaces
    #: disagree about a name rather than merely spelling it differently.
    #: Read by the p-code use/def naming layer
    #: (:mod:`smallworld.instructions.pcode_naming`), which cannot consult
    #: the Ghidra machine defs -- they import Ghidra's Java classes and so
    #: need a running JVM. Empty for platforms where the two agree.
    ghidra_register_aliases: typing.Dict[str, str] = {}

    #: Segment name -> the register holding that segment's base address, for
    #: platforms that model segmented addressing with a base register rather
    #: than only a selector. Read by
    #: :meth:`.BSIDMemoryReferenceOperand.address`, which needs it to resolve
    #: `fs:[0x28]` to fsbase+0x28 rather than to 0x28, and by the p-code
    #: use/def naming layer, which uses it to recognize a flattened
    #: segment-relative reference. Empty where the platform models no segment
    #: base -- i386 keeps only the 2-byte fs/gs selectors, so a 32-bit
    #: segment-relative access stays unresolvable until it grows one.
    segment_base_registers: typing.Dict[str, str] = {}

    @property
    @abc.abstractmethod
    def architecture(self) -> Architecture:
        """Architecture ID for this platform"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def byteorder(self) -> Byteorder:
        """Byteorder for this platform"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def address_size(self) -> int:
        """Address size in bytes"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def capstone_arch(self) -> int:
        """Capstone Architecture ID"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def capstone_mode(self) -> int:
        """Capstone Mode ID"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def conditional_branch_mnemonics(self) -> typing.Set[str]:
        """Set of conditional branch mnemonics"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def compare_mnemonics(self) -> typing.Set[str]:
        """Set of comparison mnemonics"""
        raise NotImplementedError()

    delay_slot_mnemonics: typing.Set[str] = set()
    """Set of delay slot mnemonics"""

    implicit_dereference_mnemonics: typing.Set[str] = set()
    """Set of mnemonics for instructions that implicitly dereference a register"""

    compare_branch_mnemonics: typing.Set[str] = set()
    """Conditional branch mnemonics whose comparison reads registers or
    memory directly (MIPS beq, AArch64 cbz, x86 jrcxz) rather than
    condition flags set by an earlier compare."""

    status_register: typing.Optional[str] = None
    """The register holding the condition flags (rflags, cpsr, nzcv), or
    None where the platform models none. Named so analyses can tell it
    apart from data registers: a compare's read of it (ARM data-processing
    reads the carry through the barrel shifter) is not a compared value."""

    @property
    @abc.abstractmethod
    def pc_register(self) -> str:
        """Program Counter register name"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def sp_register(self) -> str:
        """Stack Pointer register name"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def general_purpose_registers(self) -> typing.List[str]:
        """List of general-purpose register names"""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def registers(self) -> typing.Dict[str, RegisterDef]:
        """Mapping from canonical register names to register definitions"""
        raise NotImplementedError()

    def __init_subclass__(cls, **kwargs):
        # for_platform() memoizes misses; a PlatformDef defined after a miss
        # must be findable.
        super().__init_subclass__(**kwargs)
        utils.forget_subclass_misses()

    @classmethod
    def for_platform(cls, platform: Platform):
        """A new instance of the PlatformDef for `platform`.

        The class is found by searching the subclasses of `cls` for one
        whose ``architecture`` and ``byteorder`` match, and the result is
        memoized per ``(cls, architecture, byteorder)``:

        * a hit is kept for the life of the process, so a PlatformDef
          defined later for a platform that has already been looked up does
          not replace the class found first;
        * a miss is kept only until the next PlatformDef subclass is
          defined, so a PlatformDef defined after a failed lookup is found
          by the next one.

        Each call returns a new instance.

        Raises:
            ValueError: On any failure: no PlatformDef matches `platform`,
                or the search or the constructor raised. The original
                exception is the ``__cause__``.
        """
        try:
            return utils.find_subclass(
                cls,
                lambda x: x.architecture == platform.architecture
                and x.byteorder == platform.byteorder,
                cache_key=(platform.architecture, platform.byteorder),
            )
        except Exception as e:
            # Callers rely on any failure surfacing as ValueError. Exception,
            # not a bare except, so KeyboardInterrupt and SystemExit propagate.
            raise ValueError(f"No platform definition for {platform}") from e
