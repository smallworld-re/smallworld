import typing

from .... import platforms
from . import stack


class PowerPCStack(stack.DescendingStack):
    """A stack for a PPC 32-bit CPU"""

    def get_pointer(self) -> int:
        return (self.address + self.size) - self.get_used()

    def get_alignment(self) -> int:
        return 4

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for PowerPC")


class PowerPC32Stack(PowerPCStack):
    """A stack for a PPC 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.POWERPC32, platforms.Byteorder.BIG
    )


class PowerPC64Stack(PowerPCStack):
    """A stack for a PPC 64-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.POWERPC64, platforms.Byteorder.BIG
    )
