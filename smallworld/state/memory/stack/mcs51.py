import typing

from .... import exceptions, platforms
from ....platforms.defs.mcs51 import MCS51_IDATA_BASE
from ... import state
from . import stack


class MCS51Stack(stack.Stack):
    """A stack for the Intel 8051.

    The 8051's stack grows up through its internal RAM, and SP points at the
    last byte pushed: PUSH increments SP and then writes.  Mapped at a flat
    address in SmallWorld's 8051 memory map (internal RAM starts at
    ``MCS51_IDATA_BASE``), so :meth:`get_pointer` returns a flat address, and
    the value for the SP register is ``(get_pointer() - MCS51_IDATA_BASE) &
    0xFF``: SP is 8 bits, so for a stack at the start of internal RAM, with
    nothing pushed, it is 0xFF, and the first push wraps it to 0.

    Raises:
        ConfigurationError: If the stack is not within internal RAM's 256
            bytes, which SP indexes.
    """

    platform = platforms.Platform(platforms.Architecture.MCS51, platforms.Byteorder.BIG)

    def __init__(self, address: int, size: int) -> None:
        if (
            not MCS51_IDATA_BASE
            <= address
            <= address + size
            <= MCS51_IDATA_BASE + 0x100
        ):
            raise exceptions.ConfigurationError(
                f"An 8051 stack must be in internal RAM, {hex(MCS51_IDATA_BASE)} to "
                f"{hex(MCS51_IDATA_BASE + 0x100)}, not {hex(address)} to "
                f"{hex(address + size)}"
            )
        super().__init__(address, size)
        # Nothing pushed yet, so SP points just below the region.
        self.stack_pointer = address - 1

    def get_alignment(self) -> int:
        return 1

    def push(self, value: state.Value) -> int:
        self._is_safe(value)
        self[self.stack_pointer + 1 - self.address] = value
        self.stack_pointer += value.get_size()
        return self.stack_pointer

    def push_integer(self, integer: int, size: int, label: str) -> int:
        # LCALL pushes its return address low byte first, and RET pops it high
        # byte first, so multi-byte values sit on the stack little-endian
        # although the 8051 is otherwise big-endian.
        value = state.IntegerValue(integer, size, label, platforms.Byteorder.LITTLE)
        return self.push(value)

    @classmethod
    def initialize_stack(cls, argv: typing.List[bytes], *args, **kwargs):
        raise NotImplementedError("Stack initialization not implemented for MCS51")
