import abc
import typing

from .... import exceptions, platforms, utils


class PandaMachineDef(metaclass=abc.ABCMeta):
    """Container class for Unicorn architecture-specific definitions"""

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
    def panda_arch(self) -> str:
        """The panda architecture to use"""
        raise NotImplementedError("This is an abstract method.")

    _registers: typing.Dict[str, typing.Optional[str]] = {}

    def panda_reg(self, name: str) -> str:
        if name in self._registers:
            res = self._registers[name]
            if res is None:
                raise exceptions.UnsupportedRegisterError(
                    f"Register {name} not recognized by Panda for {self.arch}:{self.byteorder}"
                )
            return res
        else:
            raise ValueError(
                f"Unknown register for {self.arch}:{self.byteorder}: {name}"
            )

    def check_panda_reg(self, name: str) -> bool:
        """Convert a register name to panda cpu field, index, mask

        This must cover all names defined in the CPU state model
        for this arch/mode/byteorder, or return 0,
        which always indicates an invalid register
        """
        if name in self._registers and self._registers[name] is not None:
            return True
        else:
            return False

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
            raise ValueError(
                f"No machine model for {platform.architecture}:{platform.byteorder}"
            )
