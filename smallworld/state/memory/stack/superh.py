import typing

from .... import platforms
from . import stack


class SuperHStack(stack.DescendingStack):
    """Shared SuperH stack.

    The SH ABI puts the stack pointer in r15 and grows the stack downward
    (``<stackpointer register="r15" space="ram" growth="negative"/>`` in Ghidra's
    SuperH4 compiler spec), with 4-byte alignment - SH's data organization sets a
    default pointer alignment of 4 and aligns 8-byte types to 4 as well.

    Deliberately has no ``platform``, so ``find_subclass`` never selects it.
    """

    def get_alignment(self) -> int:
        return 4

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for SuperH")


class SH2AFPUStack(SuperHStack):
    """A stack for an SH-2A-FPU CPU."""

    platform = platforms.Platform(
        platforms.Architecture.SUPERH_SH2A_FPU, platforms.Byteorder.BIG
    )


class SuperH4BEStack(SuperHStack):
    """A stack for an SH-4 CPU, big-endian."""

    platform = platforms.Platform(
        platforms.Architecture.SUPERH_SH4, platforms.Byteorder.BIG
    )


class SuperH4ELStack(SuperHStack):
    """A stack for an SH-4 CPU, little-endian."""

    platform = platforms.Platform(
        platforms.Architecture.SUPERH_SH4, platforms.Byteorder.LITTLE
    )
