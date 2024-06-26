from __future__ import annotations

import abc
import copy
import logging
import typing

from .. import state

logger = logging.getLogger(__name__)


class Emulator(metaclass=abc.ABCMeta):
    """An emulator base class.

    Defines the interface for emulators.
    """

    @abc.abstractmethod
    def read_register(self, name: str) -> int:
        """Read a value from a register.

        Arguments:
            name: The name of the register to read.

        Returns:
            The register value.
        """

        return 0

    @abc.abstractmethod
    def write_register(
        self,
        name: str,
        value: typing.Optional[int],
        label: typing.Optional[typing.Any] = None,
    ) -> None:
        """Write a value to a register.

        Arguments:
            name: The name of the register to write.
            value: The value to write.
        """

        pass

    @abc.abstractmethod
    def get_pages(self, num_pages: int) -> int:
        """maps this many fresh pages into the emulator

        Returns:
          The start address of the new pages
        """
        return 0

    @abc.abstractmethod
    def read_memory(self, address: int, size: int) -> typing.Optional[bytes]:
        """Read memory from a specific address.

        Arguments:
            address: The address to read.
            size: The content of the read.

        Returns:
            `size` bytes read from `address`.
        """

        return b""

    @abc.abstractmethod
    def write_memory(
        self,
        address: int,
        value: typing.Optional[bytes],
        label: typing.Optional[typing.Dict[int, typing.Any]] = None,
    ) -> None:
        """Write memory at a specific address.

        This will allocate memory if necessary.

        Arguments:
            address: The address to write.
            value: The value to write.
        """

        pass

    @abc.abstractmethod
    def load(self, code: state.Code) -> None:
        """Load a binary for execution.

        Arguments:
            code: The executable to load.
        """

        pass

    @abc.abstractmethod
    def hook(
        self,
        address: int,
        function: typing.Callable[[Emulator], None],
        finish: bool = False,
    ) -> None:
        """Register a hook at the given address.

        Arguments:
            address: The address to hook.
            function: The hook function.
            finish: If `True` step out of the current call after running the
                hook function.
        """

        pass

    @abc.abstractmethod
    def run(self) -> None:
        """Start execution."""

        pass

    @abc.abstractmethod
    def step(self, single_insn: bool = False) -> bool:
        """Single-step execution.

        Emulators may support block and/or instruction stepping,
        and the default mode may change per emulator.

        Arguments:
            single_insn: If true, step by one instruction

        Returns:
            `True` if we have reached the program exit point, otherwise `False`.
        """

        pass

    @abc.abstractmethod
    def __repr__(self) -> str:
        """Instance stringifier.

        Implementation required.
        """

        return ""

    @property
    @abc.abstractmethod
    def PAGE_SIZE(self):
        pass

    def emulate(
        self, cpu: state.CPU, single_step=False, steps: typing.Optional[int] = None
    ):
        """Emulate execution of some code.

        Arguments:
            cpu: A state class from which emulation should begin.

        Returns:
            The final cpu of the system.
        """
        cpu.apply(self)
        if steps is not None:
            while steps > 0 and not self.step(single_insn=True):
                steps -= 1
        elif single_step:
            while not self.step(single_insn=True):
                pass
        else:
            self.run()
        cpu = copy.deepcopy(cpu)
        cpu.load(self)
        return cpu
