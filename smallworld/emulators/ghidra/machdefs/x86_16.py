import typing

from ....platforms import Architecture, Byteorder
from .i386 import i386MachineDef


class X86RealModeMachineDef(i386MachineDef):
    """Ghidra machine definition for 16-bit x86 in real mode.

    Sleigh keeps the linear address of the next instruction in EIP, and IP
    is its low half. It also infers the code segment from that address,
    as ``(EIP >> 4) & 0xf000``: near calls push the low 16 bits of the
    linear address, and returns add it back onto cs. Both are only right
    when cs is a multiple of 0x1000, so code must run from a segment that
    starts on a 64 KiB boundary.
    """

    arch = Architecture.X86_16
    byteorder = Byteorder.LITTLE

    # Near pointers are 2 bytes, but offsets into the linear address space
    # are 4.
    ram_address_size = 4

    _registers = {
        **i386MachineDef._registers,
        "pc": "eip",
        # NOTE: Sleigh's EIP is the linear pc, not the offset into cs.
        "eip": None,
    }

    def evaluate_userop(
        self, name: str, inputs: typing.List[int]
    ) -> typing.Optional[int]:
        if name == "segment":
            # Real-mode address computation, as the processor spec defines it.
            base, offset = inputs
            return (base << 4) + offset
        return None
