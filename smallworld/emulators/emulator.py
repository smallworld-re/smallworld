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
    def map_memory(self, size: int, address: typing.Optional[int] = None) -> int:
        """Map memory of a given size.

        Arguments:
            size: The size of the allocation.
            address: The requested address of the allocation. If not provided,
                the emulator is free choose the location of the allocation
                based on available and mapped memory.

        Returns:
            The start address of the allocation.
        """

        return 0

    def write_memory(
        self,
        address: int,
        value: typing.Optional[bytes],
        label: typing.Optional[typing.Dict[int, typing.Any]] = None,
    ) -> None:
        """Write memory at a specific address.

        Note: written memory should already be mapped by some call to
        `map_memory()`.

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
        """Register an execution hook at the given address.

        Arguments:
            address: The address to hook.
            function: The hook function.
            finish: If `True` step out of the current call after running the
                hook function.
        """

        pass

    @abc.abstractmethod
    def hook_memory(
        self,
        address: int,
        size: int,
        on_read: typing.Optional[typing.Callable[[Emulator, int, int], bytes]] = None,
        on_write: typing.Optional[
            typing.Callable[[Emulator, int, int, bytes], None]
        ] = None,
    ) -> None:
        """Register a memory hook at a given address.

        Can register separate callbacks for hooking reads and writes.
        At least one of the two callbacks must be specified.

        Arguments:
            address: The address to hook
            size: The number of bytes to hook
            on_read: Callback to execute on read
            on_write: Callback to execute on write
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

    def emulate(
        self, cpu: state.CPU, single_step=False, steps: typing.Optional[int] = None
    ):
        """Emulate execution of some code.

        Arguments:
            cpu: A state class from which emulation should begin.

        Returns:
            The final state of the system.
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

    @abc.abstractmethod
    def __repr__(self) -> str:
        return ""
