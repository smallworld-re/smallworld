from ... import platforms
from .. import state
from . import mips


class MIPSELCPUState(mips.MIPSCPUState):
    """Auto-generated CPU state for mips:mips32:little

    Generated from Pcode language MIPS:LE:32:default,
    and Unicorn package unicorn.mips_const
    """

    @classmethod
    def get_platform(cls) -> platforms.Platform:
        return platforms.Platform(
            platforms.Architecture.MIPS32, platforms.Byteorder.LITTLE
        )

    def __init__(self):
        super().__init__()
        # *** Accumulator Registers ***
        # MIPS uses these to implement 64-bit results
        # from 32-bit multiplication, amongst others.
        self.ac0 = state.Register("ac0", size=8)
        self.lo = state.RegisterAlias("lo0", self.ac0, size=4, offset=0)
        self.hi = state.RegisterAlias("hi0", self.ac0, size=4, offset=4)
        self.ac1 = state.Register("ac1", size=8)
        self.lo1 = state.RegisterAlias("lo1", self.ac1, size=4, offset=0)
        self.hi1 = state.RegisterAlias("hi1", self.ac1, size=4, offset=4)
        self.ac2 = state.Register("ac2", size=8)
        self.lo2 = state.RegisterAlias("lo2", self.ac2, size=4, offset=0)
        self.hi2 = state.RegisterAlias("hi2", self.ac2, size=4, offset=4)
        self.ac3 = state.Register("ac3", size=8)
        self.lo3 = state.RegisterAlias("lo3", self.ac3, size=4, offset=0)
        self.hi3 = state.RegisterAlias("hi3", self.ac3, size=4, offset=4)
