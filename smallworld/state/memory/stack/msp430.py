import typing

from .... import platforms
from . import stack


class MSP430Stack(stack.DescendingStack):
    """A stack for a TI msp430 CPU"""

    platform = platforms.Platform(
        platforms.Architecture.MSP430, platforms.Byteorder.LITTLE
    )

    def get_alignment(self) -> int:
        return 2

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for MIPS32")
