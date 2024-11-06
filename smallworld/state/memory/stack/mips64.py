import typing

from .... import platforms
from . import stack


class MIPS64Stack(stack.DescendingStack):
    """A stack for a MIPS 64-bit CPU"""

    def get_pointer(self) -> int:
        return (self.address + self.size) - self.get_used()

    def get_alignment(self) -> int:
        return 4

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for MIPS64")


class MIPS64BEStack(MIPS64Stack):
    """A stack for a big-endian MIPS 64-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.MIPS64, platforms.Byteorder.BIG
    )


class MIPS64ELStack(MIPS64Stack):
    """A stack for a little-endian MIPS 64-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.MIPS64, platforms.Byteorder.LITTLE
    )
