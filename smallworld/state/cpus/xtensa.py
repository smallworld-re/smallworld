import typing

from ... import platforms, state
from . import cpu


class XTensa(cpu.CPU):
    """CPU for XTensa, little-endian

    Like RISC-V, which shares its lineage,
    xtensa has a very small core architecture
    with a metric boatload of optional extensions.

    One noteable option is that xtensa uses register windows.
    I'm not putting up with that shit for now.
    """

    def get_general_purpose_registers(self) -> typing.List[str]:
        return [f"a{i}" for i in range(0, 16)]

    def __init__(self):
        super().__init__()
        # *** General Purpose Registers ***
        # a0 is also the default link register, but it doesn't get an alias
        self.a0 = state.Register("a0", 4)
        self.add(self.a0)
        # a1 is also the stack pointer
        self.a1 = state.Register("a1", 4)
        self.add(self.a1)
        self.sp = state.RegisterAlias("sp", self.a1, 4, 0)
        self.add(self.sp)
        self.a2 = state.Register("a2", 4)
        self.add(self.a2)
        self.a3 = state.Register("a3", 4)
        self.add(self.a3)
        self.a4 = state.Register("a4", 4)
        self.add(self.a4)
        self.a5 = state.Register("a5", 4)
        self.add(self.a5)
        self.a6 = state.Register("a6", 4)
        self.add(self.a6)
        self.a7 = state.Register("a7", 4)
        self.add(self.a7)
        self.a8 = state.Register("a8", 4)
        self.add(self.a8)
        self.a9 = state.Register("a9", 4)
        self.add(self.a9)
        self.a10 = state.Register("a10", 4)
        self.add(self.a10)
        self.a11 = state.Register("a11", 4)
        self.add(self.a11)
        self.a12 = state.Register("a12", 4)
        self.add(self.a12)
        self.a13 = state.Register("a13", 4)
        self.add(self.a13)
        self.a14 = state.Register("a14", 4)
        self.add(self.a14)
        self.a15 = state.Register("a15", 4)
        self.add(self.a15)

        # *** Program Counter ***
        self.pc = state.Register("pc", 4)
        self.add(self.pc)

        # *** Shift Amount Register ***
        # This thing is actually 6 bits.
        self.sar = state.Register("sar", 4)
        self.add(self.sar)


class XTensaEL(XTensa):
    platform = platforms.Platform(
        platforms.Architecture.XTENSA, platforms.Byteorder.LITTLE
    )


class XTensaBE(XTensa):
    platform = platforms.Platform(
        platforms.Architecture.XTENSA, platforms.Byteorder.BIG
    )
