import abc
import typing

from .... import exceptions, platforms, utils

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

    uc_cpu: typing.Optional[int] = None
    """The Unicorn CPU ID, if needed"""

    cpsr_fixed_bits: int = 0
    """ARM CPSR bits the platform holds set, such as E on a BE8 CPU"""

    @property
    @abc.abstractmethod
    def uc_mode(self) -> int:
        """The unicorn mode ID

        This must include an byteorder flag
        """
        return 0

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
                f"Unknown register for {self.arch}:{self.byteorder}: {name}"
            )

    def is_fetch_fault(self, intno: int) -> bool:
        """Whether interrupt `intno` reports a failed instruction fetch

        Some cores report a fetch from unmapped memory as an exception
        rather than as a Unicorn fetch error.
        """
        return False

    def uc_pc_value(self, pc: int) -> int:
        """The value to give Unicorn for ``pc``, as a start address or register.

        Unicorn takes some execution modes from the low bit of the pc, both
        when emu_start() begins and when the pc register is written; an even
        value leaves such a mode. A machine that runs in one sets that bit
        here.
        """
        return pc

    def handle_interrupt(self, intno: int, pc: int) -> None:
        """Handle a Unicorn interrupt

        Unicorn doesn't always translate interrupts into exceptions;
        we may need to give it some help.

        Arguments:
            intno: QEMU interrupt index
        """
        raise exceptions.EmulationExecExceptionFailure(
            f"Unhandled interrupt {intno} at {hex(pc)}", pc
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
