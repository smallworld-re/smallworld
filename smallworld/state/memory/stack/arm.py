import typing

from .... import platforms
from . import stack


class ARM32Stack(stack.DescendingStack):
    """A stack for an ARM 32-bit CPU"""

    def get_alignment(self) -> int:
        return 8

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for ARM32")


class ARMv4Stack(ARM32Stack):
    """A stack for an ARMv4 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V4, platforms.Byteorder.LITTLE
    )


class ARMv4tStack(ARM32Stack):
    """A stack for an ARMv4t 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V4T, platforms.Byteorder.LITTLE
    )


class ARMv5tStack(ARM32Stack):
    """A stack for an ARMv5t 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V5T, platforms.Byteorder.LITTLE
    )


class ARMv4BEStack(ARM32Stack):
    """A stack for a big-endian ARMv4 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V4, platforms.Byteorder.BIG
    )


class ARMv4tBEStack(ARM32Stack):
    """A stack for a big-endian ARMv4t 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V4T, platforms.Byteorder.BIG
    )


class ARMv5tBEStack(ARM32Stack):
    """A stack for a big-endian ARMv5t 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V5T, platforms.Byteorder.BIG
    )


class ARMv6kStack(ARM32Stack):
    """A stack for an ARMv6k 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V6K, platforms.Byteorder.LITTLE
    )


class ARMv6mStack(ARM32Stack):
    """A stack for an ARMv6m 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V6M, platforms.Byteorder.LITTLE
    )


class ARMv7mStack(ARM32Stack):
    """A stack for an ARMv7m 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V7M, platforms.Byteorder.LITTLE
    )


class ARMv7emStack(ARM32Stack):
    """A stack for an ARMv7e-m 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V7EM, platforms.Byteorder.LITTLE
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


class ARMv8aStack(ARM32Stack):
    """A stack for an ARMv8a 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V8A, platforms.Byteorder.LITTLE
    )


class ARMv8rStack(ARM32Stack):
    """A stack for an ARMv8r 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V8R, platforms.Byteorder.LITTLE
    )


class ARMv8mStack(ARM32Stack):
    """A stack for an ARMv8m 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V8M, platforms.Byteorder.LITTLE
    )


class ARMv6kBEStack(ARM32Stack):
    """A stack for a big-endian ARM6K 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V6K, platforms.Byteorder.BIG
    )


class ARMv7aBEStack(ARM32Stack):
    """A stack for a big-endian ARM7-A 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V7A, platforms.Byteorder.BIG
    )


class ARMv7rBEStack(ARM32Stack):
    """A stack for a big-endian ARM7-R 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V7R, platforms.Byteorder.BIG
    )


class ARMv8aBEStack(ARM32Stack):
    """A stack for a big-endian ARM8-A 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V8A, platforms.Byteorder.BIG
    )


class ARMv8rBEStack(ARM32Stack):
    """A stack for a big-endian ARM8-R 32-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.ARM_V8R, platforms.Byteorder.BIG
    )
