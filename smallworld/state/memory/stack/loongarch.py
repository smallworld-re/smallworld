import typing

from .... import platforms
from . import stack


class LoongArchStack(stack.DescendingStack):
    """A stack for a LoongArch CPU"""

    def get_alignment(self) -> int:
        return 4

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for LoongArch")


class LoongArch64Stack(LoongArchStack):
    """A stack for a LoongArch 64-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.LOONGARCH64, platforms.Byteorder.LITTLE
    )
