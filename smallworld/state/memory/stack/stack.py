import abc
import typing

from .... import platforms, utils
from ... import state
from .. import memory


class Stack(memory.Memory):
    """A stack-like region of memory with convenient operations like push and pop."""

    def __init__(self, address: int, size: int) -> None:
        self.stack_pointer = address + size
        super().__init__(address, size)

    @property
    @abc.abstractmethod
    def platform(self) -> platforms.Platform:
        """The platform for which this stack is intended."""
        pass

    @classmethod
    def get_platform(cls) -> platforms.Platform:
        """Retrieve the platform for this stack."""
        if not isinstance(cls.platform, platforms.Platform):
            raise TypeError(f"{cls.__name__}.platform is not a Platform object")
        return cls.platform

    def get_pointer(self) -> int:
        """Get the current stack pointer.

        Returns:
          The current value of the stack pointer.
        """
        return self.stack_pointer

    @abc.abstractmethod
    def get_alignment(self) -> int:
        """Get the alignment for this stack.

        Returns:
          The alignment for this stack.
        """
        pass

    @abc.abstractmethod
    def push(self, value: state.Value) -> int:
        """Push a value to the stack.

        Arguments:
            value: The value to be pushed.
        Returns:
            The stack pointer after the push.
        """
        pass

    def push_integer(self, integer: int, size: int, label: str) -> int:
        """Push an integer to the stack.

        Arguments:
            integer: The integer value to be pushed.
            size: The size in bytes for the integer on the stack.
            label: The label for the integer.
        Returns:
            The stack pointer after the push.
        """

        value = state.IntegerValue(integer, size, label)
        return self.push(value)

    def push_bytes(self, content: typing.Union[bytes, bytearray], label: str) -> int:
        """Push some bytes to the stack.

        Arguments:
            content: The bytes to push.
            label: The label for the bytes.

        Returns:
            The stack pointer after the push.
        """
        value = state.BytesValue(content, label)
        return self.push(value)

    def push_ctype(self, content: typing.Any, label: str) -> int:
        """Push some structured bytes to the stack.

        Arguments:
            content: The ctypes structured bytes.
            label: The label for the bytes.
        Returns:
            The stack pointer after the push.
        """
        value = state.Value.from_ctypes(content, label)
        return self.push(value)

    def push_symbolic(self, size: int, label: str) -> int:
        """Push an uninitialized placeholder to the stack.

        Arguments:
            size: The number of bytes to push.
            label: The label for the bytes
        Returns:
            The stack pointer after the push.
        """
        value = state.SymbolicValue(size, None, None, label)
        return self.push(value)

    @classmethod
    def for_platform(cls, platform: platforms.Platform, address: int, size: int):
        """Create a stack for this platform.

        Arguments:
            platform: The platform for which this stack is intended.
            address: Start address for this stack.
            size: Size of requested stack, in bytes.
        """

        def check(x: typing.Type[Stack]):
            if x.get_platform():
                return (
                    x.get_platform().architecture == platform.architecture
                    and x.get_platform().byteorder == platform.byteorder
                )
            return False

        try:
            return utils.find_subclass(cls, check, address, size)
        except ValueError:
            raise ValueError(f"No stack for {platform}")


class DescendingStack(Stack):
    """A stack that grows down, i.e., a push will decrease the stack pointer."""

    def push(self, value: state.Value) -> int:
        self._is_safe(value)
        offset = self.stack_pointer - self.address - value.get_size()
        self[offset] = value
        self.stack_pointer -= value.get_size()
        return offset


__all__ = ["Stack"]
