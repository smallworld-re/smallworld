import abc
import inspect
import typing

from .... import platforms, utils

# from ....platforms import Architecture


class UnicornMachineDef(metaclass=abc.ABCMeta):
    """Container class for Unicorn architecture-specific definitions"""

    @property
    @abc.abstractmethod
    def arch(self) -> platforms.Architecture:
        """The architecture ID"""
        raise NotImplementedError("Abstract unicorn machine def has no architecture")

    @property
    @abc.abstractmethod
    def byteorder(self) -> platforms.Byteorder:
        """The byte order"""
        raise NotImplementedError("Abstract unicorn machine def has no byteorder")

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

    _registers: typing.Dict[str, typing.Tuple[typing.Any, str, int, int]] = {}

    def uc_reg(self, name: str) -> typing.Tuple[typing.Any, str, int, int]:
        """Convert a register name to unicorn constant

        This must cover all names defined in the CPU state model
        for this arch/mode/byteorder, or return 0,
        which always indicates an invalid register
        """
        if name in self._registers:
            return self._registers[name]
        else:
            raise ValueError(
                f"Unknown register for {self.arch}:{self.byteorder}: {name}"
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


def populate_registers(arch_info, unicorn_consts):
    def find_uc_const(reg_name):
        ew = f"_{reg_name.upper()}"
        for name, num in inspect.getmembers(unicorn_consts):
            if name.endswith(ew) and "REG" in name:
                return (name, num)
        return None

    registers = {}
    for reg_name, info in arch_info.items():
        (base_reg_name, (start, end)) = info
        (ucstr, ucnum) = find_uc_const(reg_name)
        registers[reg_name] = (ucnum, base_reg_name, start, end)

    return registers
