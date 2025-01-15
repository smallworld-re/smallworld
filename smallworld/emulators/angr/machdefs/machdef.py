import abc
import typing

import angr
import archinfo

from .... import exceptions, platforms, utils


class AngrMachineDef:
    """Container class for angr architecture-specific definitions"""

    @property
    @abc.abstractmethod
    def arch(self) -> platforms.Architecture:
        """The architecture ID"""
        raise NotImplementedError("This is an abstract method.")

    @property
    @abc.abstractmethod
    def byteorder(self) -> platforms.Byteorder:
        """The byte order"""
        raise NotImplementedError("This is an abstract method.")

    @property
    @abc.abstractmethod
    def angr_arch(self) -> archinfo.arch.Arch:
        """The angr architecture to use"""
        raise NotImplementedError("This is an abstract method.")

    @property
    @abc.abstractmethod
    def pc_reg(self) -> str:
        """The program counter register name"""
        return ""

    # Is this thumb?
    # Almost always no, but angr needs to ask.
    is_thumb: bool = False

    # The angr execution engine.
    # Setting this to "none" uses the default Vex engine.
    # This only needs to be overridden if you're a pcode machine.
    angr_engine: typing.Optional[typing.Type[angr.engines.UberEnginePcode]] = None

    # Does angr support single-instruction stepping for this ISA.
    #
    # Instructions with delay slots cannot be lifted into VEX
    # without also lifting the instruction in the delay slot.
    #
    # This flag indicates that this machine uses such instructions,
    # and is not safe to step in this manner.
    supports_single_step: bool = True

    _registers: typing.Dict[str, str]

    def angr_reg(self, name: str) -> typing.Tuple[int, int]:
        """Find the offset and size of a register in the angr state's register file."""
        if name not in self._registers:
            raise KeyError(f"Unknown register for {self.arch}:{self.byteorder}: {name}")
        name = self._registers[name]

        if name not in self.angr_arch.registers:
            raise exceptions.UnsupportedRegisterError(
                f"Register {name} not recognized by angr for {self.arch}:{self.byteorder}"
            )
        return self.angr_arch.registers[name]

    def successors(self, state: angr.SimState, **kwargs) -> typing.Any:
        """Compute successor states for this architecture

        This allows a particular machine definition
        to compensate for cases where the default
        successor computation produces inaccurate results.

        For the overwhelming majority of machine models,
        the default should be sufficient.

        The biggest case to date is to handle
        user-defined operations in pcode.
        These are treated as illegal ops by angr,
        and there is currently no way to intercept their processing.

        Arguments:
            state: The angr state for which to compute successors
            kwargs: See AngrObjectFactory.successors()

        Returns:
            The successor states of `state`.
        """
        if state.project is None:
            raise exceptions.ConfigurationError("Angr state had no project.")
        return state.project.factory.successors(state, **kwargs)

    @classmethod
    def for_platform(cls, platform: platforms.Platform):
        """Find the appropriate MachineDef for your architecture

        Arguments:
            arch: The architecture ID you want
            mode: The mode ID you want
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
        except:
            raise ValueError(f"No machine model for {platform}")


class PcodeMachineDef(AngrMachineDef):
    """Container class for pcode-dependent angr architecture-specific definitions"""

    @property
    @abc.abstractmethod
    def pcode_language(self) -> str:
        """The pcode language ID string"""
        return ""

    @property
    def angr_arch(self) -> archinfo.arch.Arch:
        return self._angr_arch

    angr_engine: typing.Optional[
        typing.Type[angr.engines.UberEnginePcode]
    ] = angr.engines.UberEnginePcode

    def __init__(self):
        self._angr_arch = archinfo.ArchPcode(self.pcode_language)
