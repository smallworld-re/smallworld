import typing

from .... import platforms
from . import stack


class SPARC32Stack(stack.DescendingStack):
    """A stack for a 32-bit SPARC CPU."""

    platform = platforms.Platform(
        platforms.Architecture.SPARC32, platforms.Byteorder.BIG
    )

    def get_alignment(self) -> int:
        # The SPARC ABI keeps %sp doubleword-aligned.
        return 8

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for SPARC")
