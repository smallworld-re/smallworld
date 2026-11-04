import abc
import typing

import claripy
from ghidra.app.plugin.processors.sleigh import SleighLanguageProvider
from ghidra.program.model.lang import Language, LanguageID, Register

from .... import exceptions, platforms, utils
from ....platforms.defs.platformdef import PlatformDef

Userop = typing.Callable[[typing.Any, str, typing.Sequence[int]], typing.Optional[int]]
"""A userop SmallWorld runs itself: ``(emulator, mnemonic, args) -> output``."""


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

    # Userops the emulator steps over instead of running,
    # for SLEIGH that calls a userop Ghidra's emulator can't run
    # on this language.
    nop_userops: typing.FrozenSet[str] = frozenset()

    # Userops SmallWorld runs itself, for SLEIGH that calls a userop Ghidra's
    # emulator can't run on this language. Each maps to a function taking the
    # emulator, the instruction's mnemonic and the userop's arguments as
    # unsigned integers, and returning its output's value, or None for a
    # userop with no output.
    userops: typing.Mapping[str, Userop] = {}

    # Registers whose halves Ghidra holds in the opposite order to the
    # architecture, for a language that lays out its registers for the other
    # byte order.
    swapped_halves: typing.FrozenSet[str] = frozenset()

    # Bits of a register that the language keeps in registers of their own,
    # as {register: {bit: SLEIGH register}}. Each SLEIGH register holds its
    # bit as a 0 or 1 byte; reads merge the bits in, and writes split them
    # back out.
    split_bits: typing.Mapping[str, typing.Mapping[int, str]] = {}

    _registers: typing.Dict[str, typing.Optional[str]]

    def __init__(self):
        # Load the Pcode language definition
        slp = SleighLanguageProvider.getSleighLanguageProvider()
        langID = LanguageID(self.language_id)
        self.language: Language = slp.getLanguage(langID)
        assert self.language is not None

    def userop_name(self, op) -> typing.Optional[str]:
        """The name of the userop this p-code op calls, if it calls one."""
        if op.getOpcode() != op.CALLOTHER:
            return None
        return str(self.language.getUserDefinedOpName(int(op.getInput(0).getOffset())))

    def is_nop_userop(self, op) -> bool:
        """Whether this p-code op calls one of `nop_userops`."""
        if not self.nop_userops:
            return False
        return self.userop_name(op) in self.nop_userops

    def userop(self, op) -> typing.Optional["Userop"]:
        """The implementation of the userop this p-code op calls, if SmallWorld
        has one."""
        if not self.userops:
            return None
        name = self.userop_name(op)
        return None if name is None else self.userops.get(name)

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

    def fix_register_bytes(self, name: str, data: bytes) -> bytes:
        """Convert a register's bytes between Ghidra's order and ours

        This is its own inverse, so it serves for reads and writes.
        """
        if name not in self.swapped_halves:
            return data
        half = len(data) // 2
        return data[half:] + data[:half]

    def fix_register_bv(self, name: str, bv: claripy.ast.bv.BV) -> claripy.ast.bv.BV:
        """:meth:`fix_register_bytes` for a symbolic value"""
        if name not in self.swapped_halves:
            return bv
        half = bv.size() // 2
        return claripy.Concat(bv[half - 1 : 0], bv[bv.size() - 1 : half])

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
