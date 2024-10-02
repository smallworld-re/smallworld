import abc
import typing

from .. import state
from . import memory


class Heap(memory.Memory):
    @abc.abstractmethod
    def allocate(self, value: state.Value) -> int:
        pass

    @abc.abstractmethod
    def free(self, address: int) -> None:
        pass

    def allocate_integer(self, integer: int, size: int, label: str) -> int:
        value = state.IntegerValue(integer, size, label)
        return self.allocate(value)

    def allocate_bytes(
        self, content: typing.Union[bytes, bytearray], label: str
    ) -> int:
        value = state.BytesValue(content, label)
        return self.allocate(value)

    def allocate_ctype(self, content, label: str) -> int:
        value = state.Value.from_ctypes(content, label)
        return self.allocate(value)


class BumpAllocator(Heap):
    def allocate(self, value: state.Value) -> int:
        self._is_safe(value)
        offset = self.get_used()
        self[offset] = value
        return self.address + offset

    def free(self, address: int) -> None:
        raise NotImplementedError("freeing with a BumpAllocator is not yet implemented")


__all__ = ["Heap", "BumpAllocator"]
