import abc
import typing

from smallworld import platforms
from smallworld.emulators import Emulator

from .. import state
from . import memory


class Heap(memory.Memory):
    """A heap-like memory region, with convenient operations like allocate and free."""

    @abc.abstractmethod
    def allocate(self, value: state.Value) -> int:
        """Allocate space for and write a value to the heap.

        Arguments:
            value: The value to go on the heap.
        Returns:
            The address at which the value was allocated.
        """
        pass

    @abc.abstractmethod
    def free(self, address: int) -> None:
        """Free space on the heap for previously allocated data.

        Arguements:
            address: The start address of the previously allocated data.
        """
        pass

    def allocate_integer(
        self, integer: int, size: int, label: str, byteorder: platforms.Byteorder
    ) -> int:
        """Allocate space for and write an integer to the heap.

        Arguments:
            integer: The integer to go on the heap.
            size: The number of bytes to allocate to the integer.
            label: The label to give to the allocated region containing the integer.
        Returns:
            The address at which the integer was allocated.
        """
        value = state.IntegerValue(integer, size, label, byteorder=byteorder)
        return self.allocate(value)

    def allocate_bytes(
        self, content: typing.Union[bytes, bytearray], label: typing.Optional[str]
    ) -> int:
        """Allocate space for and write bytes to the heap.

        Arguments:
            content: The bytes to go on the heap.
            label: The label to give to the bytes on the heap.
        Returns:
            The address at which the integer was allocated.
        """
        value = state.BytesValue(content, label)
        return self.allocate(value)

    def allocate_ctype(self, content, label: str) -> int:
        """Allocate space for and write structured bytes to the heap.

        Arguements:
            content: The ctypes-structured data to go on the heap.
            label: The label to give to the data bytes on the heap.

        Returns:
            The address at which the structured data was allocated.
        """
        value = state.Value.from_ctypes(content, label)
        return self.allocate(value)


class BumpAllocator(Heap):
    """A simple bump allocator heap."""

    def allocate(self, value: state.Value) -> int:
        self._is_safe(value)
        offset = self.get_used()
        self[offset] = value
        return self.address + offset

    def free(self, address: int) -> None:
        pass


class CheckedBumpAllocator(Heap):
    """A simple bump allocator heap that uses a shadow memory to check reads and write. It will also check for UAF bugs."""

    def __init__(
        self, address: int, size: int, guard_bytes: int, *args, **kwargs
    ) -> None:
        super().__init__(address, size, *args, **kwargs)
        self._shadow = [0] * size
        self._current_free_offset = 0
        self._guard_size = guard_bytes
        self._allocations: typing.Dict[int, int] = {}

    def get_used(self) -> int:
        return self._current_free_offset - self.address

    def _is_safe(self, value: state.Value):
        if (
            self.get_used() + value.get_size() + self._guard_size
        ) > self.get_capacity():
            raise ValueError("Memory is full")

    def allocate(self, value: state.Value) -> int:
        self._is_safe(value)
        value_size = value.get_size()

        offset = self._current_free_offset
        self._current_free_offset += value_size + self._guard_size

        for i in range(value_size):
            self._shadow[offset + i] = 1

        self._allocations[offset] = value_size
        self[offset] = value
        return self.address + offset

    def free(self, address: int) -> None:
        if address in self._allocations:
            offset = address - self.address
            size = self._allocations[address]
            for i in range(size):
                self._shadow[offset + i] = 2
            del self._allocations[address]
        else:
            raise ValueError(f"Invalid Free at {hex(address)}")

    def check_access(
        self,
        emulator: Emulator,
        address: int,
        size: int,
        content: bytes,
    ):
        offset = address - self.address
        if (offset + size) > size:
            raise ValueError(f"Invalid access at {hex(address)} of size {size}")

        for i in range(size):
            shadow_byte = self._shadow[offset + i]
            if shadow_byte == 1:
                continue
            elif shadow_byte == 0:
                raise ValueError(f"Access uninitialized bytes at {hex(address + i)}")
            elif shadow_byte == 2:
                raise ValueError(f"Access freed memory at {hex(address + i)}")

        return content

    def apply(self, emulator: typing.Any) -> None:
        super().apply(emulator)
        emulator.hook_memory_read(
            self.address, self.address + self.size, self.check_access
        )
        emulator.hook_memory_write(
            self.address, self.address + self.size, self.check_access
        )


__all__ = ["Heap", "BumpAllocator", "CheckedBumpAllocator"]
