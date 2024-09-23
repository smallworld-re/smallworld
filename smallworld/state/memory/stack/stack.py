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
        pass

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
    def for_platform(cls, platform: platforms.Platform):
        try:
            return utils.find_subclass(
                cls,
                lambda x: x.get_platform().architecture == platform.architecture
                and x.get_platform().byteorder == platform.byteorder,
            )
        except ValueError:
            raise ValueError(f"No stack for {platform}")


class DescendingStack(Stack):
    def push(self, value: state.Value) -> int:
        self._is_safe(value)
        offset = (self.get_capacity() - 1) - self.get_used()
        self[offset] = value
        return offset


class x86_64Stack(DescendingStack):
    @classmethod
    def get_platform(cls) -> platforms.Platform:
        return platforms.Platform(
            platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
        )

    def get_pointer(self) -> int:
        return ((self.address + self.size) - self.get_used() - 8) & 0xFFFFFFFFFFFFFFF0

    def get_alignment(self) -> int:
        return 16

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        s = cls(*args, **kwargs)
        argv_address = []
        total_strings_bytes = 0
        for i, arg in enumerate(argv):
            arg_size = len(arg)
            total_strings_bytes += arg_size
            argv_address.append(
                (i, s.push_bytes(bytes(arg, "utf-8"), label=f"argv[{i}]"))
            )

        argc = len(argv)
        total_space = (8 * (argc + 2)) + total_strings_bytes
        padding = 16 - (total_space % 16)
        s.push_bytes(bytes(padding), label="stack alignment padding bytes")
        s.push_integer(0, size=8, label="null terminator of argv array")
        for i, addr in reversed(argv_address):
            s.push_integer(addr, size=8, label=f"pointer to argv[{i}]")
        s.push_integer(argc, size=8, label="argc")
        return s


__all__ = ["Stack"]
