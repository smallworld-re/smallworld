import abc
import typing

import unicorn

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

    def configure_engine(self, engine: unicorn.Uc) -> None:
        """Set up a newly created Unicorn engine

        This is for CPU state the machine state doesn't model,
        but that user-space code expects, such as enabled FPUs.
        The default does nothing.

        Arguments:
            engine: The new engine
        """
        pass

    def disassembler_mode(self, engine: typing.Any, mode: int) -> int:
        """The capstone mode to decode the next instruction with.

        For a machine whose instruction set can change at runtime. The
        default is the platform's mode, unchanged.

        Arguments:
            engine: The Unicorn engine
            mode: The platform's capstone mode

        Returns:
            The capstone mode for the instruction set the CPU runs now
        """
        return mode

    def pc_from_engine(self, engine: typing.Any, value: int) -> int:
        """Convert the engine's program counter register to SmallWorld's pc.

        Arguments:
            engine: The Unicorn engine
            value: The contents of the register that `pc` maps to

        Returns:
            The address of the next instruction
        """
        return value

    def pc_to_engine(self, engine: typing.Any, pc: int) -> int:
        """Convert SmallWorld's pc to the engine's program counter register.

        Arguments:
            engine: The Unicorn engine
            pc: The address of the next instruction

        Returns:
            The value to write to the register that `pc` maps to
        """
        return pc

    def pc_to_start(self, engine: typing.Any, pc: int) -> int:
        """Convert SmallWorld's pc to the address emu_start() begins at.

        Unicorn takes some execution modes from the low bit of the start
        address, as it does when the pc register is written, so this is
        `pc_to_engine()` unless a machine's pc register is not the address.

        Arguments:
            engine: The Unicorn engine
            pc: The address of the next instruction

        Returns:
            The address to pass to emu_start()
        """
        return self.pc_to_engine(engine, pc)

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
