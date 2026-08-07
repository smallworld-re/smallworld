import typing

from .... import platforms
from . import stack


class TriCoreStack(stack.DescendingStack):
    """A stack for a TriCore CPU."""

    platform = platforms.Platform(
        platforms.Architecture.TRICORE, platforms.Byteorder.LITTLE
    )

    def get_alignment(self) -> int:
        return 8

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for TriCore")
