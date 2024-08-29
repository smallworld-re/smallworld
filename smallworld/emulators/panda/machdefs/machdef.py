import abc
import typing
import pandare

from .... import utils


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
    def byteorder(self) -> str:
        """The byte order"""
        return ""

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

    _registers: typing.Dict[str, int] = {}

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
