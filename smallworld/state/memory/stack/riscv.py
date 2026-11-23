import typing

from .... import platforms
from . import stack


class RISCV32Stack(stack.DescendingStack):
    """A stack for a RISCV 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.RISCV32, platforms.Byteorder.LITTLE
    )

    def get_alignment(self) -> int:
        # The ilp32 psABI keeps the 16-byte alignment of lp64
        return 16

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for RISCV32")


class RISCV64Stack(stack.DescendingStack):
    """A stack for a RISCV 64-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.RISCV64, platforms.Byteorder.LITTLE
    )

    def get_alignment(self) -> int:
        return 16

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for RISCV64")
