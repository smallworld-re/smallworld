import typing

from .... import platforms
from . import stack
from ... import state

class ARM32Stack(stack.DescendingStack):
    
    def get_pointer(self) -> int:
        return (self.address + self.size) - self.get_used()

    def get_alignment(self) -> int:
        return 8

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for ARM32")

class ARMv5tStack(ARM32Stack):
    platform = platforms.Platform(platforms.Architecture.ARM_V5T, platforms.Byteorder.LITTLE)
class ARMv6mStack(ARM32Stack):
    platform = platforms.Platform(platforms.Architecture.ARM_V6M, platforms.Byteorder.LITTLE)
class ARMv6mStack(ARM32Stack):
    platform = platforms.Platform(platforms.Architecture.ARM_V6M_THUMB, platforms.Byteorder.LITTLE)
class ARMv7mStack(ARM32Stack):
    platform = platforms.Platform(platforms.Architecture.ARM_V7M, platforms.Byteorder.LITTLE)
class ARMv7rStack(ARM32Stack):
    platform = platforms.Platform(platforms.Architecture.ARM_V7R, platforms.Byteorder.LITTLE)
class ARMv7aStack(ARM32Stack):
    platform = platforms.Platform(platforms.Architecture.ARM_V7A, platforms.Byteorder.LITTLE)

