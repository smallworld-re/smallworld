import abc
import enum
import typing

from ghidra.app.plugin.processors.sleigh import SleighLanguageProvider
from ghidra.program.model.lang import Language, LanguageID, Register

from .... import exceptions, platforms, utils
from ....platforms.defs.platformdef import PlatformDef


class _UserOpEnumMeta(enum.EnumMeta):
    # Let `opnum in SomeUserOp` test raw userop numbers.
    def __contains__(cls, obj):
        if isinstance(obj, int):
            return obj in cls._value2member_map_
        return super().__contains__(obj)


class GhidraUserOp(enum.IntEnum, metaclass=_UserOpEnumMeta):
    """Base for a machine's table of SLEIGH user-defined operations.

    Each member is the operation's number, followed by its name, a handler
    and a description, as in the angr backend's Xtensa and LoongArch tables.
    The handler is called as ``handler(emulator, op)`` with the CALLOTHER
    p-code op, in place of running it, and must perform the operation itself.
    """

    def __new__(
        cls, val: int, name: str = "", handler: typing.Any = None, desc: str = ""
    ):
        obj = int.__new__(cls, val)
        obj._value_ = val
        obj.short_name = name
        obj.handler = handler
        obj.description = desc
        return obj

    def __init__(
        self, val: int, name: str = "", handler: typing.Any = None, desc: str = ""
    ):
        self._value_: int = val
        self.short_name: str = name
        self.handler: typing.Any = handler
        self.description: str = desc

    def __repr__(self):
        return f"{hex(self.value)}: {self.short_name} - {self.description}"


class GhidraMachineDef:
    """Container class for ghdra architecture-specific definitions"""

    @property
    @abc.abstractmethod
    def arch(self) -> platforms.Architecture:
        """The architecture ID"""
        raise NotImplementedError("This is an abstract method")

    @property
    @abc.abstractmethod
    def byteorder(self) -> platforms.Byteorder:
        """The byte order"""
        raise NotImplementedError("This is an abstract method")

    @property
    def language_id(self) -> str:
        """The Pcode (SLEIGH) language id for this machine.

        Sourced from the platform definition -- the single, JVM-free home
        for this datum -- rather than duplicated on each machine def.
        """
        platdef = PlatformDef.for_platform(
            platforms.Platform(self.arch, self.byteorder)
        )
        lang = platdef.ghidra_language_id
        assert lang is not None, (
            f"{type(platdef).__name__} has no ghidra_language_id for "
            f"{self.arch}:{self.byteorder}"
        )
        return lang

    # Does Pcode support single-instruction stepping for this ISA.
    #
    # Instructions with delay slots can't be lifted into Pcode
    # without also lifting the instruction in the delay slot.
    #
    # This flag indicates that this machine uses such instructions,
    # and is not safe to step in this manner
    supports_single_step: bool = True

    #: Address spaces SmallWorld's flat memory map covers, as
    #: (Ghidra space name, flat base address, size).  None means the
    #: language's default space alone, at flat address 0, which is every
    #: von Neumann machine.  A Harvard machine such as the 8051 lists each of
    #: its spaces, and the emulator translates between the two.  The default
    #: (code) space must sit at flat address 0, so the program counter is a
    #: flat address too.
    address_spaces: typing.Optional[typing.Tuple[typing.Tuple[str, int, int], ...]] = (
        None
    )

    #: The SLEIGH user-defined operations (CALLOTHER) this machine
    #: implements in Python, as a :class:`GhidraUserOp` enum, for operations
    #: the language leaves to its host and Ghidra's emulator does not
    #: provide.  None means the emulator runs CALLOTHER ops as Ghidra does.
    userops: typing.Optional[typing.Type["GhidraUserOp"]] = None

    _registers: typing.Dict[str, typing.Optional[str]]

    def update_derived_state(self, emulator: typing.Any) -> None:
        """Recompute machine state the SLEIGH language leaves out.

        Called before and after every instruction, so state the hardware
        derives continuously from other state - such as the 8051's parity
        flag, a function of the accumulator - is current whenever an
        instruction or the user reads it.  Most machines have none.

        Arguments:
            emulator: The emulator.
        """
        pass

    def __init__(self):
        # Load the Pcode language definition
        slp = SleighLanguageProvider.getSleighLanguageProvider()
        langID = LanguageID(self.language_id)
        self.language: Language = slp.getLanguage(langID)
        assert self.language is not None

    def pcode_reg(self, name: str) -> Register:
        if name not in self._registers:
            raise KeyError(f"Unknown register for {self.arch}:{self.byteorder}: {name}")
        if self._registers[name] is None:
            raise exceptions.UnsupportedRegisterError(
                f"Register {name} not recognized by pcode for {self.arch}:{self.byteorder}"
            )
        reg = self.language.getRegister(self._registers[name])
        assert reg is not None, name
        return reg

    @classmethod
    def for_platform(cls, platform: platforms.Platform):
        """Find the appropriate MachineDef for your architecture

        Arguments:
            arch: The architecture ID you want
            byteorder: The byteorderness you want

        Returns:
            An instance of the appropriate MachineDef

        Raises:
            ValueError: If no MachineDef subclass matches your request
        """
        try:
            return utils.find_subclass(
                cls,
                lambda x: x.arch == platform.architecture
                and x.byteorder == platform.byteorder,
            )
        except ValueError as e:
            # find_subclass raises ValueError for the no-match case; narrow to
            # it so a genuine error from the matched MachineDef's __init__ (or
            # KeyboardInterrupt/SystemExit) propagates instead of being masked.
            raise ValueError(f"No machine model for {platform}") from e
