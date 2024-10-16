import typing

from .... import platforms
from . import stack


class MIPSStack(stack.DescendingStack):
    """A stack for a MIPS 32-bit CPU"""

    def get_pointer(self) -> int:
        return (self.address + self.size) - self.get_used()

    def get_alignment(self) -> int:
        return 4

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for MIPS32")


class MIPSBEStack(MIPSStack):
    """A stack for a big-endian MIPS 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.MIPS32, platforms.Byteorder.BIG
    )


class MIPSELStack(MIPSStack):
    """A stack for a little-endian MIPS 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.MIPS32, platforms.Byteorder.LITTLE
    )
