import abc
import typing

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

    def allocate_integer(self, integer: int, size: int, label: str) -> int:
        """Allocate space for and write an integer to the heap.

        Arguments:
            integer: The integer to go on the heap.
            size: The number of bytes to allocate to the integer.
            label: The label to give to the allocated region containing the integer.
        Returns:
            The address at which the integer was allocated.
        """
        value = state.IntegerValue(integer, size, label)
        return self.allocate(value)

    def allocate_bytes(
        self, content: typing.Union[bytes, bytearray], label: str
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
        raise NotImplementedError("freeing with a BumpAllocator is not yet implemented")


__all__ = ["Heap", "BumpAllocator"]
