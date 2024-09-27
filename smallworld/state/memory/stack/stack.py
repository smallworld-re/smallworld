import abc
import typing

from .... import platforms, utils
from ... import state
from .. import memory


class Stack(memory.Memory):

    @property
    @abc.abstractmethod
    def platform(self) -> platforms.Platform:
        pass

    @classmethod
    def get_platform(cls) -> platforms.Platform:
        return cls.platform

    @abc.abstractmethod
    def get_pointer(self) -> int:
        pass

    @abc.abstractmethod
    def get_alignment(self) -> int:
        pass

    @abc.abstractmethod
    def push(self, value: state.Value) -> int:
        pass

    def push_integer(self, integer: int, size: int, label: str) -> int:
        value = state.IntegerValue(integer, size, label)
        return self.push(value)

    def push_bytes(self, content: typing.Union[bytes, bytearray], label: str) -> int:
        value = state.BytesValue(content, label)
        return self.push(value)

    def push_ctype(self, content, label: str) -> int:
        value = state.Value.from_ctypes(content, label)
        return self.push(value)


    @classmethod
    def for_platform(cls, platform: platforms.Platform, address: int, size: int):
        def check(x):
            if x.get_platform():
                return x.get_platform().architecture == platform.architecture and x.get_platform().byteorder == platform.byteorder
            return False

        try:
            return utils.find_subclass(cls, check, address, size)
        except ValueError:
            raise ValueError(f"No stack for {platform}")


class DescendingStack(Stack):
    def push(self, value: state.Value) -> int:
        self._is_safe(value)
        offset = (self.get_capacity() - 1) - self.get_used()
        self[offset] = value
        return offset

__all__ = ["Stack"]
