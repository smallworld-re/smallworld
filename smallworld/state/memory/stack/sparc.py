import typing

from .... import platforms
from . import stack


class SPARC32Stack(stack.DescendingStack):
    """A stack for a 32-bit SPARC CPU.

    The SPARC ABI has every caller reserve at least 92 bytes at %sp: a
    64-byte register-window save area, the hidden struct-return word, and
    home slots for %o0-%o5, which a callee may write through its %fp.  This
    stack does not reserve them; code that starts a function should push 96
    bytes (92, kept doubleword-aligned) before taking `get_pointer()`.
    """

    platform = platforms.Platform(
        platforms.Architecture.SPARC32, platforms.Byteorder.BIG
    )

    def get_alignment(self) -> int:
        # The SPARC ABI keeps %sp doubleword-aligned.
        return 8

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for SPARC")
