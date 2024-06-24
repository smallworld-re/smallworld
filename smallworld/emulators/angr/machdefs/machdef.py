import abc
import typing

import angr
import archinfo

from .... import utils


class AngrMachineDef:
    """Container class for angr architecture-specific definitions"""

    @property
    @abc.abstractmethod
    def arch(self) -> str:
        """The architecture ID string"""
        return ""

    @property
    @abc.abstractmethod
    def mode(self) -> str:
        """The mode ID string"""
        return ""

    @property
    @abc.abstractmethod
    def byteorder(self) -> str:
        """The byte order"""
        return ""

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
    angr_engine: typing.Optional[angr.engines.engine.SimEngineBase] = None

    _registers: typing.Dict[str, str]

    def angr_reg(self, name: str) -> typing.Tuple[int, int]:
        """Find the offset and size of a register in the angr state's register file."""
        if name not in self._registers:
            raise KeyError(
                f"Unknown register for {self.arch}:{self.mode}:{self.byteorder}: {name}"
            )
        name = self._registers[name]

        if name not in self.angr_arch.registers:
            raise ValueError(
                f"Register {name} not recognized by angr for {self.arch}:{self.mode}:{self.byteorder}"
            )
        return self.angr_arch.registers[name]

    @classmethod
    def for_arch(cls, arch: str, mode: str, byteorder: str):
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
                lambda x: x.arch == arch
                and x.mode == mode
                and x.byteorder == byteorder,
            )
        except:
            raise ValueError(f"No machine model for {arch}:{mode}:{byteorder}")


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

    angr_engine = angr.engines.UberEnginePcode

    def __init__(self):
        self._angr_arch = archinfo.ArchPcode(self.pcode_language)
