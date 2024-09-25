import abc
import typing

from .... import utils, platforms
#from ....platforms import Architecture

architecture_to_arch_mode = {

    platforms.Architecture.X86_32: ("x86", "32"),
    platforms.Architecture.X86_64: ("x86", "64"),
    platforms.Architecture.AARCH64: ("aarch64", "v8a"),
    platforms.Architecture.MIPS32: ("mips", "mips32"),
    platforms.Architecture.MIPS64: ("mips", "mips64"),
    platforms.Architecture.ARM_V5T: ("arm", "v5t"),
    platforms.Architecture.ARM_V6M: ("arm", "v6m"),
    platforms.Architecture.ARM_V6M_THUMB: ("arm", "v6m-thumb"),
    platforms.Architecture.ARM_V7M: ("arm", "v7m"),
    platforms.Architecture.ARM_V7R: ("arm", "v7r"),
    platforms.Architecture.ARM_V7A: ("arm", "v7a"),
    # we dont have these yet...
    platforms.Architecture.POWERPC64: (None, None),
    platforms.Architecture.POWERPC32: (None, None),
}

class UnicornMachineDef(metaclass=abc.ABCMeta):
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
    def byteorder(self) -> str:
        """The byte order"""
        return ""

    @property
    @abc.abstractmethod
    def uc_arch(self) -> int:
        """The Unicorn architecture ID"""
        return 0

    @property
    @abc.abstractmethod
    def uc_mode(self) -> int:
        """The unicorn mode ID

        This must include an byteorder flag
        """
        return 0

    @property
    @abc.abstractmethod
    def cs_arch(self) -> int:
        """The capstone arch ID"""
        return 0

    @property
    @abc.abstractmethod
    def cs_mode(self) -> int:
        """The capstone mode ID

        This must include an byteorder flag
        """
        return 0

    @property
    @abc.abstractmethod
    def pc_reg(self) -> str:
        """The name of the Program Counter register for this machine"""
        return ""

    _registers: typing.Dict[str, int] = {}

    def uc_reg(self, name: str) -> int:
        """Convert a register name to unicorn constant

        This must cover all names defined in the CPU state model
        for this arch/mode/byteorder, or return 0,
        which always indicates an invalid register
        """
        if name in self._registers:
            return self._registers[name]
        else:
            raise ValueError(
                f"Unknown register for {self.arch}:{self.mode}:{self.byteorder}: {name}"
            )

    @classmethod
    def for_platform(cls, platform: platforms.Platform):
        """Find the appropriate MachineDef for your architecture

        Arguments:
            platform: platform metadata

        Returns:
            An instance of the appropriate MachineDef

        Raises:
            ValueError: If no MachineDef subclass matches your request
        """

        (arch, mode) = architecture_to_arch_mode[platform.architecture]
        if arch is None:
            raise NotImplementedException
        try:

            return utils.find_subclass(
                cls,
                lambda x: x.arch == arch
                and x.mode == mode
                and x.byteorder == platform.byteorder,
            )
        except:
            raise ValueError(f"No machine model for {arch}:{mode}:{byteorder}")

