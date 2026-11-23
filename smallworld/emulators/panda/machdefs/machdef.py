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

    _state_registers: typing.FrozenSet[str] = frozenset()
    """Registers PANDA's register accessors don't reach.

    The machine def reads and writes these in the CPU's state itself, through
    ``read_state_register`` and ``write_state_register``.
    """

    mem: typing.Optional[str] = None
    """The guest RAM size to give PANDA, if the machine needs a particular one."""

    checks_fetches: bool = False
    """Whether SmallWorld checks instruction fetches against its memory map.

    PANDA checks every read and write against SmallWorld's memory map, but
    leaves an unmapped fetch to QEMU, which faults on it. A machine whose board
    has memory of its own there doesn't fault, so it sets this, and PANDA
    reports a fetch from memory SmallWorld didn't map as unmapped.
    """

    def setup_cpu(self, panda_obj, panda_cpu) -> None:
        """Configure the CPU's state once PANDA has created it."""
        pass

    def pc_written(self, panda_obj, panda_cpu) -> None:
        """Fix up the CPU's state after SmallWorld writes the program counter."""
        pass

    def read_isa_mode(self, panda_obj, panda_cpu) -> typing.Optional[int]:
        """The CPU's instruction-set mode, where PANDA's registers can't reach it.

        See :meth:`.Emulator.get_isa_mode`. None, the default, leaves it to
        the emulator's generic path through the register the platform names.
        """
        return None

    def write_isa_mode(self, mode: int, panda_obj, panda_cpu) -> bool:
        """Set the CPU's instruction-set mode, where PANDA's registers can't
        reach it.

        See :meth:`.Emulator.set_isa_mode`. Returns whether it was set; False,
        the default, leaves it to the emulator's generic path.
        """
        return False

    def is_state_register(self, name: str) -> bool:
        return name in self._state_registers

    def read_state_register(self, name: str, panda_obj, panda_cpu) -> int:
        raise exceptions.UnsupportedRegisterError(
            f"Register {name} not recognized by Panda for {self.arch}:{self.byteorder}"
        )

    def write_state_register(self, name: str, value: int, panda_obj, panda_cpu) -> None:
        raise exceptions.UnsupportedRegisterError(
            f"Register {name} not recognized by Panda for {self.arch}:{self.byteorder}"
        )

    def panda_reg(self, name: str, panda_obj, panda_cpu) -> str:
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

    def configure_cpu(self, panda_obj, panda_cpu) -> None:
        """Set up the CPU once PANDA's machine is initialized

        This is for CPU state the machine state doesn't model,
        but that user-space code expects, such as enabled FPUs.
        The default does nothing.

        Arguments:
            panda_obj: The Panda object
            panda_cpu: Its CPU
        """
        pass

    def handle_interrupt(self, intno: int, pc: int) -> None:
        """Translate a PANDA CPU exception index into a smallworld exception.

        PANDA (like QEMU) surfaces some memory faults as raw CPU exceptions
        through ``cb_before_handle_exception`` rather than through the
        instruction-bounds check, so per-arch machine defs override this to
        classify them (e.g. an unmapped instruction fetch -> an
        ``EmulationFetchUnmappedFailure`` carrying ``pc``). The default reports
        a generic error, preserving the prior behaviour for unclassified
        exceptions.

        Arguments:
            intno: The PANDA/QEMU exception index.
            pc: The address the CPU faulted on (the attempted fetch target).
        """
        raise exceptions.EmulationError(f"Panda exception {intno} at {hex(pc)}")

    def check_panda_reg(self, name: str, panda_obj, panda_cpu) -> bool:
        """Convert a register name to panda cpu field, index, mask

        This must cover all names defined in the CPU state model
        for this arch/mode/byteorder, or return 0,
        which always indicates an invalid register
        """
        if self.is_state_register(name):
            return True
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
