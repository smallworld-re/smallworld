import typing

from .... import platforms
from . import stack


class X86RealModeStack(stack.DescendingStack):
    """A stack for a 16-bit x86 CPU in real mode.

    Real-mode ``sp`` is an offset from the stack segment, ``ss * 16``, so the
    stack must start on a paragraph (16-byte) boundary and fit in one 64 KiB
    segment. :meth:`get_pointer` returns the linear address, like every other
    stack; load ``ss`` from :meth:`get_segment` and ``sp`` from
    :meth:`get_offset`.
    """

    platform = platforms.Platform(
        platforms.Architecture.X86_16, platforms.Byteorder.LITTLE
    )

    def __init__(self, address: int, size: int) -> None:
        if address % 16 != 0:
            raise ValueError(
                f"real-mode stack must start on a 16-byte boundary, not {address:#x}"
            )
        if size > 0x10000:
            raise ValueError(
                f"real-mode stack must fit in one 64 KiB segment, not {size:#x} bytes"
            )
        super().__init__(address, size)

    def get_alignment(self) -> int:
        return 2

    def get_segment(self) -> int:
        """Get the stack segment, the value for ``ss``."""
        return self.address >> 4

    def get_offset(self) -> int:
        """Get the stack pointer as an offset from the stack segment, the
        value for ``sp``.

        An empty 64 KiB stack has sp 0, which wraps to 0xfffe on the first
        push."""
        return (self.get_pointer() - self.address) & 0xFFFF

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError(
            "Stack initialization not implemented for x86 real mode"
        )
