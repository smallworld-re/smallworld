from __future__ import annotations

import abc
import typing

from .. import platform as _platform
from .. import utils


class Emulator(utils.MetadataMixin, metaclass=abc.ABCMeta):
    """An emulation environment.

    Arguments:
        platform: Platform metadata for emulation.
    """

    def __init__(self, platform: _platform.Platform):
        self.platform: _platform.Platform = platform
        """Configured platform metadata."""

    @abc.abstractmethod
    def read_register_content(self, name: str) -> int:
        """Read the content of a register.

        Arguments:
            name: The name of the register.

        Returns:
            The register's content.
        """

        return 0

    def read_register_type(self, name: str) -> typing.Optional[typing.Any]:
        """Read the type of a register.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Arguments:
            name: The name of the register.

        Returns:
            The register's type.
        """

        return None

    def read_register_label(self, name: str) -> typing.Optional[str]:
        """Read the label of a register.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Arguments:
            name: The name of the register.

        Returns:
            The register's label.
        """

        return None

    def read_register(self, name: str) -> int:
        """A helper to read the content of a register.

        Arguments:
            name: The name of the register.

        Returns:
            The register's content.
        """

        return self.read_register_content(name)

    @abc.abstractmethod
    def write_register_content(self, name: str, content: int) -> None:
        """Write some content to a register.

        Arguments:
            name: The name of the register to write.
            content: The content to write.
        """

        pass

    def write_register_type(
        self, name: str, type: typing.Optional[typing.Any] = None
    ) -> None:
        """Write the type of a register.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Arguments:
            name: The name of the register.
            type: The type of the register to write. To unset the register
                type, this may be set to None.
        """

        pass

    def write_register_label(
        self, name: str, label: typing.Optional[str] = None
    ) -> None:
        """Write the label of a register.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Arguments:
            name: The name of the register.
            label: The label of the register to write. To unset the register
                label, this may be set to None.
        """

        pass

    def write_register(self, name: str, content: int) -> None:
        """A helper to write the content of a register.

        Arguments:
            name: The name of the register.
            content: The content to write.
        """

        return self.write_register_content(name, content)

    @abc.abstractmethod
    def read_memory_content(self, address: int, size: int) -> bytes:
        """Read memory content from a specific address.

        Arguments:
            address: The address of the memory region.
            size: The size of the memory region.

        Returns:
            `size` bytes read from `address`.
        """

        return b""

    def read_memory_type(self, address: int, size: int) -> typing.Optional[typing.Any]:
        """Read memory type from a specific address.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Arguments:
            address: The address of the memory region.
            size: The size of the memory region.

        Returns:
            The memory region's type.
        """

        return None

    def read_memory_label(self, address: int, size: int) -> typing.Optional[str]:
        """Read memory label from a specific address.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Arguments:
            address: The address of the memory region.
            size: The size of the memory region.

        Returns:
            The memory region's label.
        """

        return None

    def read_memory(self, address: int, size: int) -> bytes:
        """A helper to read memory content from a specific address.

        Arguments:
            address: The address of the memory region.
            size: The size of the memory region.

        Returns:
            `size` bytes read from `address`.
        """

        return self.read_memory_content(address, size)

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

    @abc.abstractmethod
    def write_memory_content(self, address: int, content: bytes) -> None:
        """Write content to memory at a specific address.

        Note:
            Written memory should already be mapped by some call to
            `map_memory()`.

        Arguments:
            address: The address of the memory region.
            content: The content to write.
        """

        pass

    def write_memory_type(
        self, address: int, type: typing.Optional[typing.Any] = None
    ) -> None:
        """Set the type of memory at a specific address.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Arguments:
            address: The address of the memory region.
            type: The type to write.
        """

        pass

    def write_memory_label(
        self, address: int, label: typing.Optional[str] = None
    ) -> None:
        """Set the label of memory at a specific address.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Arguments:
            address: The address of the memory region.
            label: The label to write.
        """

        pass

    def write_memory(self, address: int, content: bytes) -> None:
        """A helper to write content to memory at a specific address.

        Note:
            Written memory should already be mapped by some call to
            `map_memory()`.

        Arguments:
            address: The address of the memory region.
            content: The content to write.
        """

        self.write_memory_content(address, content)

    def hook_instruction(
        self, address: int, function: typing.Callable[[Emulator], None]
    ) -> None:
        """Register an execution hook at the given instruction address.

        The hook fires *before* the instruction executes.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Example:
            The hook function should look like::

                def hook(emulator: Emulator) -> None:
                    ...

        Arguments:
            address: The address to hook.
            function: The hook function.
        """

        raise NotImplementedError(
            f"{self.__class__.__name__}: instruction hooking not supported"
        )

    def hook_function(
        self, address: int, function: typing.Callable[[Emulator], None]
    ) -> None:
        """Register an execution hook at the given function address.

        The hook fires *instead* of the function at the given address.  This
        means that the hook function is called *before* the function at the
        given address and execution returns to the calling address after the
        hook function, skipping any code at the given address.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Example:
            The hook function should look like::

                def hook(emulator: Emulator) -> None:
                    ...

        Arguments:
            address: The address to hook.
            function: The hook function.
        """

        raise NotImplementedError(
            f"{self.__class__.__name__}: function hooking not supported"
        )

    def hook_memory_read(
        self,
        start: int,
        end: int,
        function: typing.Callable[[Emulator, int, int], bytes],
    ) -> None:
        """Register an execution hook on memory read in the given region.

        The hook fires *before* the memory read. The return value of the hook
        function is used instead of reading the target memory address.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Example:
            The hook function should look like::

                def hook(emulator: Emulator, address: int, size: int) -> bytes:
                    ...

                    return content

        Arguments:
            start: The start of the memory region to hook.
            end: The end of the memory region to hook.
            function: The hook function.
        """

        raise NotImplementedError(
            f"{self.__class__.__name__}: memory read hooking not supported"
        )

    def hook_memory_write(
        self,
        start: int,
        end: int,
        function: typing.Callable[[Emulator, int, int], None],
    ) -> None:
        """Register an execution hook on memory write in the given region.

        The hook fires *before* the memory write.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Example:
            The hook function should look like::

                def hook(emulator: Emulator, address: int, size: int, content: bytes) -> None:
                    ...

        Arguments:
            start: The start of the memory region to hook.
            end: The end of the memory region to hook.
            function: The hook function.
        """

        raise NotImplementedError(
            f"{self.__class__.__name__}: memory write hooking not supported"
        )

    def hook_interrupts(self, function: typing.Callable[[Emulator, int], None]):
        """Register an execution hook on any interrupt.

        The hook fires *before* the interrupt is processed.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Example:
            The hook function should look like::

                def hook(emulator: Emulator, interrupt: int) -> None:
                    ...

        Arguments:
            function: The hook function.
        """

        raise NotImplementedError(
            f"{self.__class__.__name__}: broad interrupt hooking not supported"
        )

    def hook_interrupt(self, function: typing.Callable[[Emulator], None]):
        """Register an execution hook on a specific interrupt.

        The hook fires *before* the interrupt is processed.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Example:
            The hook function should look like::

                def hook(emulator: Emulator) -> None:
                    ...

        Arguments:
            function: The hook function.
        """

        raise NotImplementedError(
            f"{self.__class__.__name__}: specific interrupt hooking not supported"
        )

    bounds: typing.List[typing.Tuple[int, int]] = []
    """Valid execution bounds."""

    def bound(self, start: int, end: int) -> None:
        """Add valid execution bounds.

        If execution leaves these bounds Emulators should raise
        EmulationBoundsError.

        If execution bounds are not specified, Emulators should allow execution
        anywhere.

        Arguments:
            start: The start address of a valid executable region.
            end: The end address of a valid executable region.
        """

        self.bounds.append((start, end))

    exitpoints: typing.List[int] = []
    """Exit points to stop emulation."""

    def exitpoint(self, address: int) -> None:
        """Add an exitpoint.

        If execution reaches an exitpoint emulation should stop.

        Arguments:
            address: The address of the exitpoint.
        """

        self.exitpoints.append(address)

    @abc.abstractmethod
    def step_instruction(self) -> None:
        """Single instruction step execution.

        Raises:
            EmulationBoundsError: if execution steps out of bounds.
        """

        pass

    @abc.abstractmethod
    def step_block(self) -> None:
        """Single block step execution.

        Raises:
            EmulationBoundsError: if execution steps out of bounds.
        """

        pass

    def step(self) -> None:
        """Helper for single instruction step execution.

        Raises:
            EmulationBoundsError: if execution steps out of bounds.
        """

        return self.step_instruction()

    @abc.abstractmethod
    def run(self) -> None:
        """Run execution indefinitely.

        Emulation should stop if an exitpoint is reached or execution leaves
        valid bounds.

        Raises:
            EmulationBoundsError: if execution steps out of bounds.
        """

        pass

    @abc.abstractmethod
    def __repr__(self) -> str:
        return ""


__all__ = ["Emulator"]
