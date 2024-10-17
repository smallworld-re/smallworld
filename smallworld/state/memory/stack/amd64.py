import typing

from .... import platforms
from ... import state
from . import stack


class AMD64Stack(stack.DescendingStack):
    """A stack for an AMD 64-bit CPU"""

    platform = platforms.Platform(
        platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
    )

    def get_pointer(self) -> int:
        return (self.address + self.size) - self.get_used()

    def get_alignment(self) -> int:
        return 16

    def push(self, value: state.Value) -> int:
        return super().push(value)

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        s = cls(*args, **kwargs)
        argv_address = []
        total_strings_bytes = 0
        for i, arg in enumerate(argv):
            arg_size = len(arg)
            total_strings_bytes += arg_size
            argv_address.append((i, s.push_bytes(arg, label=f"argv[{i}]")))

        argc = len(argv)
        total_space = (8 * (argc + 2)) + total_strings_bytes
        padding = 16 - (total_space % 16)
        s.push_bytes(bytes(padding), label="stack alignment padding bytes")
        s.push_integer(0, size=8, label="null terminator of argv array")
        for i, addr in reversed(argv_address):
            s.push_integer(addr, size=8, label=f"pointer to argv[{i}]")
        s.push_integer(argc, size=8, label="argc")
        return s
