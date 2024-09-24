from __future__ import annotations

import abc
import typing

from .. import platforms, utils


class Emulator(utils.MetadataMixin, metaclass=abc.ABCMeta):
    """An emulation environment.

    Arguments:
        platform: Platform metadata for emulation.
    """

    def __init__(self, platform: platforms.Platform):
        self.platform: platforms.Platform = platform
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
            The register's type
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
            `size` bytes read from `address`
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
        self, address: int, size: int, type: typing.Optional[typing.Any] = None
    ) -> None:
        """Set the type of memory at a specific address.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Arguments:
            address: The address of the memory region.
            size: The size of the memory region
            type: The type of the register to write. To unset the register
                type, this may be set to None.
        """

        pass

    def write_memory_label(
        self, address: int, size: int, label: typing.Optional[str] = None
    ) -> None:
        """Set the label of memory at a specific address.

        Note:
            Implementing this behavior is optional and not necessarily
            supported by all Emulators.

        Arguments:
            address: The address of the memory region.
            size: The size of the memory region
            label: The label of the register to write. To unset the register
                label, this may be set to None.
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

    _bounds: typing.List[typing.Tuple[int, int]] = []

    def get_bounds(self) -> typing.List[typing.Tuple[int, int]]:
        """Get a list of all registered execution bounds.

        Returns:
            A list of registered execution bounds.
        """

        return self._bounds

    def add_bound(self, start: int, end: int) -> None:
        """Add valid execution bounds.

        If execution leaves these bounds Emulators should raise
        EmulationBoundsError.

        If execution bounds are not specified, Emulators should allow execution
        anywhere.

        Arguments:
            start: The start address of a valid executable region.
            end: The end address of a valid executable region.
        """

        self._bounds.append((start, end))

    _exit_points: typing.List[int] = []

    def get_exitpoints(self) -> typing.List[int]:
        """Get a list of all registered exit points.

        Returns:
            A list of registered exit points.
        """

        return self._exit_points

    def add_exit_point(self, address: int) -> None:
        """Add an exitpoint.

        If execution reaches an exitpoint emulation should stop.

        Arguments:
            address: The address of the exitpoint.
        """

        self._exit_points.append(address)

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


class InstructionHookable(metaclass=abc.ABCMeta):
    """An Emulator mixin that supports instruction hooking."""

    @abc.abstractmethod
    def hook_instruction(
        self, address: int, function: typing.Callable[[Emulator], None]
    ) -> None:
        """Hook a specific instruction by address.

        Arguments:
            address: The address of the hook.
            function: The function to execute when the address is reached.

        Example:
            The hook function looks like::

                def hook(emulator: Emulator) -> None:
                    ...
        """

        pass

    @abc.abstractmethod
    def unhook_instruction(self, address: int) -> None:
        """Unhook a specific instruction by address.

        Arguments:
            address: The address of the hook to remove.
        """

        pass


class FunctionHookable(metaclass=abc.ABCMeta):
    """An Emulator mixin that supports function hooking."""

    @abc.abstractmethod
    def hook_function(
        self, address: int, function: typing.Callable[[Emulator], None]
    ) -> None:
        """Hook a specific function by address.

        After the hook function is called, the Emulator will step out of the
        current function so that the hook essentially replaces a function call
        to the given address.

        Arguments:
            address: The address of the hook.
            function: The function to execute when the address is reached.

        Example:
            The hook function looks like::

                def hook(emulator: Emulator) -> None:
                    ...
        """

        pass

    @abc.abstractmethod
    def unhook_function(self, address: int) -> None:
        """Unhook a specific function by address.

        Arguments:
            address: The address of the hook to remove.
        """

        pass


class MemoryReadHookable(metaclass=abc.ABCMeta):
    """An Emulator mixin that supports memory read hooking."""

    @abc.abstractmethod
    def hook_memory_read(
        self,
        start: int,
        end: int,
        function: typing.Callable[[Emulator, int, int], bytes],
    ) -> None:
        """Hook memory reads within a given range.

        Arguments:
            start: The start address of the memory range to hook.
            end: The end address of the memory range to hook.
            function: The function to execute when the memory region is read.

        Example:
            The hook function looks like::

                def hook(emulator: Emulator, address: int, size: int) -> None:
                    ...
        """

        pass

    @abc.abstractmethod
    def unhook_memory_read(self, start: int, end: int) -> None:
        """Unhook a specific memory region read by address range.

        Arguments:
            start: The start address of the memory read hook to remove.
            end: The end address of the memory read hook to remove.
        """

        pass


class MemoryWriteHookable(metaclass=abc.ABCMeta):
    """An Emulator mixin that supports memory write hooking."""

    @abc.abstractmethod
    def hook_memory_write(
        self,
        start: int,
        end: int,
        function: typing.Callable[[Emulator, int, int], bytes],
    ) -> None:
        """Hook memory writes within a given range.

        Arguments:
            start: The start address of the memory range to hook.
            end: The end address of the memory range to hook.
            function: The function to execute when the memory region is written.

        Example:
            The hook function looks like::

                def hook(emulator: Emulator, address: int, size: int, content: bytes) -> None:
                    ...
        """

        pass

    @abc.abstractmethod
    def unhook_memory_read(self, start: int, end: int) -> None:
        """Unhook a specific memory region write by address range.

        Arguments:
            start: The start address of the memory write hook to remove.
            end: The end address of the memory write hook to remove.
        """

        pass


class InterruptHookable(metaclass=abc.ABCMeta):
    """An Emulator mixin that supports interrupt hooking."""

    @abc.abstractmethod
    def hook_interrupts(self, function: typing.Callable[[Emulator, int], None]) -> None:
        """Hook any system interrupts.

        Arguments:
            function: The function to execute when an interrupt is triggered.

        Example:
            The hook function looks like::

                def hook(emulator: Emulator, interrupt: int) -> None:
                    ...
        """

        pass

    @abc.abstractmethod
    def unhook_interrupts(self) -> None:
        """Unhook all system interrupts."""

        pass

    @abc.abstractmethod
    def hook_interrupt(
        self, interrupt: int, function: typing.Callable[[Emulator], None]
    ) -> None:
        """Hook a specific system interrupt.

        Arguments:
            function: The function to execute when the interrupt is triggered.

        Example:
            The hook function looks like::

                def hook(emulator: Emulator) -> None:
                    ...
        """

        pass

    @abc.abstractmethod
    def unhook_interrupt(self, interupt: int) -> None:
        """Unhook a specific system interrupt.

        Arguments:
            interrupt: The interrupt to unhook.
        """

        pass


__all__ = [
    "Emulator",
    "InstructionHookable",
    "FunctionHookable",
    "MemoryReadHookable",
    "MemoryWriteHookable",
    "InterruptHookable",
]
