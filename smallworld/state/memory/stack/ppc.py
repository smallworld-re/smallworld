import typing

from .... import platforms
from . import stack
from ... import state

class PowerPCStack(stack.DescendingStack):
    
    def get_pointer(self) -> int:
        return (self.address + self.size) - self.get_used()

    def get_alignment(self) -> int:
        return 4

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for PowerPC")

class PowerPC32Stack(PowerPCStack):
    platform = platforms.Platform(platforms.Architecture.POWERPC32, platforms.Byteorder.BIG)

class PowerPC64Stack(PowerPCStack):
    platform = platforms.Platform(platforms.Architecture.POWERPC64, platforms.Byteorder.BIG)
