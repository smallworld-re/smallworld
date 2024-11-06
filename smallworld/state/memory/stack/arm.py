import typing

from .... import platforms
from . import stack


class ARM32Stack(stack.DescendingStack):
    """A stack for an ARM 32-bit CPU"""

    def get_pointer(self) -> int:
        return (self.address + self.size) - self.get_used()

    def get_alignment(self) -> int:
        return 8

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for ARM32")


class ARMv5tStack(ARM32Stack):
    """A stack for an ARMv5t 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V5T, platforms.Byteorder.LITTLE
    )


class ARMv6mStack(ARM32Stack):
    """A stack for an ARMv6m 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V6M, platforms.Byteorder.LITTLE
    )


class ARMv6mThumbStack(ARM32Stack):
    """A stack for an ARMv6mThumb 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V6M_THUMB, platforms.Byteorder.LITTLE
    )


class ARMv7mStack(ARM32Stack):
    """A stack for an ARMv7m 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V7M, platforms.Byteorder.LITTLE
    )


class ARMv7rStack(ARM32Stack):
    """A stack for an ARMv7r 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V7R, platforms.Byteorder.LITTLE
    )


class ARMv7aStack(ARM32Stack):
    """A stack for an ARMv7a 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V7A, platforms.Byteorder.LITTLE
    )
