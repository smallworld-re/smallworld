import typing

from .... import platforms
from . import stack


class M68KStack(stack.DescendingStack):
    """A stack for an M68K CPU"""

    platform = platforms.Platform(platforms.Architecture.M68K, platforms.Byteorder.BIG)

    def get_alignment(self) -> int:
        return 4

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for MIPS32")
