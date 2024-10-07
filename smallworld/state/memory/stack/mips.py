import typing

from .... import platforms
from . import stack
from ... import state

class MIPSStack(stack.DescendingStack):
    
    def get_pointer(self) -> int:
        return (self.address + self.size) - self.get_used()

    def get_alignment(self) -> int:
        return 4

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for MIPS32")

class MIPSBEStack(MIPSStack):
    platform = platforms.Platform(platforms.Architecture.MIPS32, platforms.Byteorder.BIG)

class MIPSELStack(MIPSStack):
    platform = platforms.Platform(platforms.Architecture.MIPS32, platforms.Byteorder.LITTLE)
