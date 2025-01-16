import typing

from .... import platforms
from . import stack


class RISCV64Stack(stack.DescendingStack):
    """A stack for a RISCV 64-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.RISCV64, platforms.Byteorder.LITTLE
    )

    def get_pointer(self) -> int:
        return (self.address + self.size) - self.get_used()

    def get_alignment(self) -> int:
        return 16

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for AArch64")
