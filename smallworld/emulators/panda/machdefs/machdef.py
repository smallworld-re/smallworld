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
