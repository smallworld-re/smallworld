import abc
import typing

import pandare

from .... import platforms, utils
from ....platforms import Byteorder

architecture_to_arch_mode = {
    platforms.Architecture.X86_32: ("x86", "32"),
    platforms.Architecture.X86_64: ("x86", "64"),
}


class PandaMachineDef(metaclass=abc.ABCMeta):
    """Container class for Unicorn architecture-specific definitions"""

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
    def byteorder(self) -> Byteorder:
        """The byte order"""
        return Byteorder.LITTLE

    @property
    @abc.abstractmethod
    def panda_arch(self) -> pandare.arch.PandaArch:
        """The angr architecture to use"""
        raise NotImplementedError("This is an abstract method.")

    @property
    @abc.abstractmethod
    def pc_reg(self) -> str:
        """The name of the Program Counter register for this machine"""
        return ""

    _registers: typing.Set[str] = set()

    def check_panda_reg(self, name: str) -> bool:
        """Convert a register name to panda cpu field, index, mask

        This must cover all names defined in the CPU state model
        for this arch/mode/byteorder, or return 0,
        which always indicates an invalid register
        """
        if name in self._registers:
            return True
        else:
            raise ValueError(
                f"Unknown register for {self.arch}:{self.mode}:{self.byteorder}: {name}"
            )

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
        (arch, mode) = architecture_to_arch_mode[platform.architecture]
        if arch is None:
            raise NotImplementedError
        try:
            return utils.find_subclass(
                cls,
                lambda x: x.arch == arch
                and x.mode == mode
                and x.byteorder == platform.byteorder,
            )
        except:
            raise ValueError(f"No machine model for {arch}:{mode}:{platform.byteorder}")
