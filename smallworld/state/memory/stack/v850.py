import typing

from .... import platforms
from . import stack


class V850Stack(stack.DescendingStack):
    """A stack for a V850 CPU."""

    platform = platforms.Platform(
        platforms.Architecture.V850, platforms.Byteorder.LITTLE
    )

    def get_alignment(self) -> int:
        return 4

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for V850")
