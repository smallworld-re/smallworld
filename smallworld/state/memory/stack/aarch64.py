import typing

from .... import platforms
from . import stack
from ... import state

class AArch64Stack(stack.DescendingStack):
    platform = platforms.Platform(platforms.Architecture.AARCH64, platforms.Byteorder.LITTLE)
    
    def get_pointer(self) -> int:
        return (self.address + self.size) - self.get_used()

    def get_alignment(self) -> int:
        return 16

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for AArch64")
