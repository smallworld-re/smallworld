import typing

from .... import platforms
from . import stack


class AMD64Stack(stack.DescendingStack):
    """A stack for an AMD 64-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
    )

    def get_alignment(self) -> int:
        return 16

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        s = cls(*args, **kwargs)
        argv_address = []
        total_strings_bytes = 0
        for i, arg in enumerate(argv):
            arg_size = len(arg)
            total_strings_bytes += arg_size
            # push_bytes returns the absolute address of the pushed value.
            argv_address.append((i, s.push_bytes(arg, label=f"argv[{i}]")))

        argc = len(argv)
        total_space = (8 * (argc + 2)) + total_strings_bytes
        # SysV requires the final RSP (at argc) to be 16-byte aligned. argc will
        # land at (address + size) - total_space - padding, so pad relative to
        # the region top rather than to total_space alone -- the latter only
        # aligns argc when the region top is itself 16-aligned.
        padding = (s.address + s.size - total_space) % 16
        s.push_bytes(bytes(padding), label="stack alignment padding bytes")
        s.push_integer(0, size=8, label="null terminator of argv array")
        for i, addr in reversed(argv_address):
            s.push_integer(addr, size=8, label=f"pointer to argv[{i}]")
        s.push_integer(argc, size=8, label="argc")
        return s
