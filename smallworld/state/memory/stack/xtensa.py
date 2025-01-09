import typing

from .... import platforms
from . import stack


class XTensaStack(stack.DescendingStack):
    """A stack for an XTensa CPU"""

    def get_pointer(self) -> int:
        return (self.address + self.size) - self.get_used()

    def get_alignment(self) -> int:
        return 4

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for XTensa")


class XTensaBEStack(XTensaStack):
    """A stack for a big-endian XTensa CPU"""

    platform = platforms.Platform(
        platforms.Architecture.XTENSA, platforms.Byteorder.BIG
    )


class XTensaELStack(XTensaStack):
    """A stack for a little-endian XTensa CPU"""

    platform = platforms.Platform(
        platforms.Architecture.XTENSA, platforms.Byteorder.LITTLE
    )
