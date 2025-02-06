import typing

from ... import platforms
from .. import state
from . import cpu


class MIPS(cpu.CPU):
    """Auto-generated CPU state for mips:mips32:big.

    Generated from Pcode language MIPS:BE:32:default, and Unicorn package
    unicorn.mips_const.
    """

    # Excluded registers:
    # - zero: Hard-wired to zero
    # - at: Reserved for assembler
    # - kX: Reserved for kernel; used as general in some ABIs
    # - fX: Floating-point registers
    # - acX: Accumulator registers
    _GENERAL_PURPOSE_REGS = [
        "v0",
        "v1",
        "a0",
        "a1",
        "a2",
        "a3",
        "t0",
        "t1",
        "t2",
        "t3",
        "t4",
        "t5",
        "t6",
        "t7",
        "t8",
        "t9",
        "s0",
        "s1",
        "s2",
        "s3",
        "s4",
        "s5",
        "s6",
        "s7",
        "s8",
    ]

    def get_general_purpose_registers(self) -> typing.List[str]:
        return self._GENERAL_PURPOSE_REGS

    def __init__(self):
        super().__init__()
        # NOTE: MIPS registers have both a name and a number.

        # *** General-Purpose Registers ***
        # Assembler-Temporary Register
        self.at = state.Register("at", size=4)
        self.add(self.at)
        self._1 = state.RegisterAlias("1", self.at, size=4, offset=0)
        self.add(self._1)
        # Return Value Registers
        self.v0 = state.Register("v0", size=4)
        self.add(self.v0)
        self._2 = state.RegisterAlias("2", self.v0, size=4, offset=0)
        self.add(self._2)
        self.v1 = state.Register("v1", size=4)
        self.add(self.v1)
        self._3 = state.RegisterAlias("3", self.v1, size=4, offset=0)
        self.add(self._3)
        # Argument Registers
        self.a0 = state.Register("a0", size=4)
        self.add(self.a0)
        self._4 = state.RegisterAlias("4", self.a0, size=4, offset=0)
        self.add(self._4)
        self.a1 = state.Register("a1", size=4)
        self.add(self.a1)
        self._5 = state.RegisterAlias("5", self.a1, size=4, offset=0)
        self.add(self._5)
        self.a2 = state.Register("a2", size=4)
        self.add(self.a2)
        self._6 = state.RegisterAlias("6", self.a2, size=4, offset=0)
        self.add(self._6)
        self.a3 = state.Register("a3", size=4)
        self.add(self.a3)
        self._7 = state.RegisterAlias("7", self.a3, size=4, offset=0)
        self.add(self._7)
        # Temporary Registers
        self.t0 = state.Register("t0", size=4)
        self.add(self.t0)
        self._8 = state.RegisterAlias("8", self.t0, size=4, offset=0)
        self.add(self._8)
        self.t1 = state.Register("t1", size=4)
        self.add(self.t1)
        self._9 = state.RegisterAlias("9", self.t1, size=4, offset=0)
        self.add(self._9)
        self.t2 = state.Register("t2", size=4)
        self.add(self.t2)
        self._10 = state.RegisterAlias("10", self.t2, size=4, offset=0)
        self.add(self._10)
        self.t3 = state.Register("t3", size=4)
        self.add(self.t3)
        self._11 = state.RegisterAlias("11", self.t3, size=4, offset=0)
        self.add(self._11)
        self.t4 = state.Register("t4", size=4)
        self.add(self.t4)
        self._12 = state.RegisterAlias("12", self.t4, size=4, offset=0)
        self.add(self._12)
        self.t5 = state.Register("t5", size=4)
        self.add(self.t5)
        self._13 = state.RegisterAlias("13", self.t5, size=4, offset=0)
        self.add(self._13)
        self.t6 = state.Register("t6", size=4)
        self.add(self.t6)
        self._14 = state.RegisterAlias("14", self.t6, size=4, offset=0)
        self.add(self._14)
        self.t7 = state.Register("t7", size=4)
        self.add(self.t7)
        self._15 = state.RegisterAlias("15", self.t7, size=4, offset=0)
        self.add(self._15)
        # NOTE: These numbers aren't out of order.
        # t8 and t9 are later in the register file than t0 - t7.
        self.t8 = state.Register("t8", size=4)
        self.add(self.t8)
        self._24 = state.RegisterAlias("24", self.t8, size=4, offset=0)
        self.add(self._24)
        self.t9 = state.Register("t9", size=4)
        self.add(self.t9)
        self._25 = state.RegisterAlias("25", self.t9, size=4, offset=0)
        self.add(self._25)
        # Saved Registers
        self.s0 = state.Register("s0", size=4)
        self.add(self.s0)
        self._16 = state.RegisterAlias("16", self.s0, size=4, offset=0)
        self.add(self._16)
        self.s1 = state.Register("s1", size=4)
        self.add(self.s1)
        self._17 = state.RegisterAlias("17", self.s1, size=4, offset=0)
        self.add(self._17)
        self.s2 = state.Register("s2", size=4)
        self.add(self.s2)
        self._18 = state.RegisterAlias("18", self.s2, size=4, offset=0)
        self.add(self._18)
        self.s3 = state.Register("s3", size=4)
        self.add(self.s3)
        self._19 = state.RegisterAlias("19", self.s3, size=4, offset=0)
        self.add(self._19)
        self.s4 = state.Register("s4", size=4)
        self.add(self.s4)
        self._20 = state.RegisterAlias("20", self.s4, size=4, offset=0)
        self.add(self._20)
        self.s5 = state.Register("s5", size=4)
        self.add(self.s5)
        self._21 = state.RegisterAlias("21", self.s5, size=4, offset=0)
        self.add(self._21)
        self.s6 = state.Register("s6", size=4)
        self.add(self.s6)
        self._22 = state.RegisterAlias("22", self.s6, size=4, offset=0)
        self.add(self._22)
        self.s7 = state.Register("s7", size=4)
        self.add(self.s7)
        self._23 = state.RegisterAlias("23", self.s7, size=4, offset=0)
        self.add(self._23)
        # NOTE: Register #30 was originally the Frame Pointer.
        # It's been re-aliased as s8, since many ABIs don't use the frame pointer.
        # Unicorn and Sleigh prefer to use the alias s8,
        # so it should be the base register.
        self.s8 = state.Register("s8", size=4)
        self.add(self.s8)
        self.fp = state.RegisterAlias("fp", self.s8, size=4, offset=0)
        self.add(self.fp)
        self._30 = state.RegisterAlias("30", self.s8, size=4, offset=0)
        self.add(self._30)
        # Kernel-reserved Registers
        self.k0 = state.Register("k0", size=4)
        self.add(self.k0)
        self._26 = state.RegisterAlias("26", self.k0, size=4, offset=0)
        self.add(self._26)
        self.k1 = state.Register("k1", size=4)
        self.add(self.k1)
        self._27 = state.RegisterAlias("27", self.k1, size=4, offset=0)
        self.add(self._27)
        # *** Pointer Registers ***
        # Zero register
        self.zero = state.FixedRegister("zero", size=4, value=0)
        self.add(self.zero)
        self._0 = state.RegisterAlias("0", self.zero, size=4, offset=0)
        self.add(self._0)
        # Global Offset Pointer
        self.gp = state.Register("gp", size=4)
        self.add(self.gp)
        self._28 = state.RegisterAlias("28", self.gp, size=4, offset=0)
        self.add(self._28)
        # Stack Pointer
        self.sp = state.Register("sp", size=4)
        self.add(self.sp)
        self._29 = state.RegisterAlias("29", self.sp, size=4, offset=0)
        self.add(self._29)
        # Return Address
        self.ra = state.Register("ra", size=4)
        self.add(self.ra)
        self._31 = state.RegisterAlias("31", self.ra, size=4, offset=0)
        self.add(self._31)
        # Program Counter
        self.pc = state.Register("pc", size=4)
        self.add(self.pc)
        # Floating Point Registers
        self.f0 = state.Register("f0", size=8)
        self.add(self.f0)
        self.f1 = state.Register("f1", size=8)
        self.add(self.f1)
        self.f2 = state.Register("f2", size=8)
        self.add(self.f2)
        self.f3 = state.Register("f3", size=8)
        self.add(self.f3)
        self.f4 = state.Register("f4", size=8)
        self.add(self.f4)
        self.f5 = state.Register("f5", size=8)
        self.add(self.f5)
        self.f6 = state.Register("f6", size=8)
        self.add(self.f6)
        self.f7 = state.Register("f7", size=8)
        self.add(self.f7)
        self.f8 = state.Register("f8", size=8)
        self.add(self.f8)
        self.f9 = state.Register("f9", size=8)
        self.add(self.f9)
        self.f10 = state.Register("f10", size=8)
        self.add(self.f10)
        self.f11 = state.Register("f11", size=8)
        self.add(self.f11)
        self.f12 = state.Register("f12", size=8)
        self.add(self.f12)
        self.f13 = state.Register("f13", size=8)
        self.add(self.f13)
        self.f14 = state.Register("f14", size=8)
        self.add(self.f14)
        self.f15 = state.Register("f15", size=8)
        self.add(self.f15)
        self.f16 = state.Register("f16", size=8)
        self.add(self.f16)
        self.f17 = state.Register("f17", size=8)
        self.add(self.f17)
        self.f18 = state.Register("f18", size=8)
        self.add(self.f18)
        self.f19 = state.Register("f19", size=8)
        self.add(self.f19)
        self.f20 = state.Register("f20", size=8)
        self.add(self.f20)
        self.f21 = state.Register("f21", size=8)
        self.add(self.f21)
        self.f22 = state.Register("f22", size=8)
        self.add(self.f22)
        self.f23 = state.Register("f23", size=8)
        self.add(self.f23)
        self.f24 = state.Register("f24", size=8)
        self.add(self.f24)
        self.f25 = state.Register("f25", size=8)
        self.add(self.f25)
        self.f26 = state.Register("f26", size=8)
        self.add(self.f26)
        self.f27 = state.Register("f27", size=8)
        self.add(self.f27)
        self.f28 = state.Register("f28", size=8)
        self.add(self.f28)
        self.f29 = state.Register("f29", size=8)
        self.add(self.f29)
        self.f30 = state.Register("f30", size=8)
        self.add(self.f30)
        self.f31 = state.Register("f31", size=8)
        self.add(self.f31)
        # *** Floating Point Control Registers ***
        # NOTE: These are taken from Sleigh, and the MIPS docs.
        # Unicorn doesn't use these names, and has a different number of registers.
        self.fir = state.Register("fir", size=4)
        self.add(self.fir)
        self.fcsr = state.Register("fcsr", size=4)
        self.add(self.fcsr)
        self.fexr = state.Register("fexr", size=4)
        self.add(self.fexr)
        self.fenr = state.Register("fenr", size=4)
        self.add(self.fenr)
        self.fccr = state.Register("fccr", size=4)
        self.add(self.fccr)
        # TODO: MIPS has a boatload of extensions with their own registers.
        # There isn't a clean join between Sleigh, Unicorn, and MIPS docs.


class MIPSEL(MIPS):
    """Auto-generated CPU state for mips:mips32:little.

    Generated from Pcode language MIPS:LE:32:default, and Unicorn package
    unicorn.mips_const.
    """

    platform = platforms.Platform(
        platforms.Architecture.MIPS32, platforms.Byteorder.LITTLE
    )

    def __init__(self):
        super().__init__()
        # *** Accumulator Registers ***
        # MIPS uses these to implement 64-bit results
        # from 32-bit multiplication, amongst others.
        self.ac0 = state.Register("ac0", size=8)
        self.add(self.ac0)
        self.lo = state.RegisterAlias("lo0", self.ac0, size=4, offset=0)
        self.add(self.lo)
        self.hi = state.RegisterAlias("hi0", self.ac0, size=4, offset=4)
        self.add(self.hi)
        self.ac1 = state.Register("ac1", size=8)
        self.add(self.ac1)
        self.lo1 = state.RegisterAlias("lo1", self.ac1, size=4, offset=0)
        self.add(self.lo1)
        self.hi1 = state.RegisterAlias("hi1", self.ac1, size=4, offset=4)
        self.add(self.hi1)
        self.ac2 = state.Register("ac2", size=8)
        self.add(self.ac2)
        self.lo2 = state.RegisterAlias("lo2", self.ac2, size=4, offset=0)
        self.add(self.lo2)
        self.hi2 = state.RegisterAlias("hi2", self.ac2, size=4, offset=4)
        self.add(self.hi2)
        self.ac3 = state.Register("ac3", size=8)
        self.add(self.ac3)
        self.lo3 = state.RegisterAlias("lo3", self.ac3, size=4, offset=0)
        self.add(self.lo3)
        self.hi3 = state.RegisterAlias("hi3", self.ac3, size=4, offset=4)
        self.add(self.hi3)


class MIPSBE(MIPS):
    """Auto-generated CPU state for mips:mips32:big.

    Generated from Pcode language MIPS:BE:32:default, and Unicorn package
    unicorn.mips_const.
    """

    platform = platforms.Platform(
        platforms.Architecture.MIPS32, platforms.Byteorder.BIG
    )

    def __init__(self):
        super().__init__()
        # *** Accumulator Registers ***
        # MIPS uses these to implement 64-bit results
        # from 32-bit multiplication, amongst others.
        self.ac0 = state.Register("ac0", size=8)
        self.add(self.ac0)
        # NOTE: Be careful: there is also a 'hi' and 'lo' register;
        # they do different things.
        self.hi0 = state.RegisterAlias("hi0", self.ac0, size=4, offset=0)
        self.add(self.hi0)
        self.lo0 = state.RegisterAlias("lo0", self.ac0, size=4, offset=4)
        self.add(self.lo0)
        self.ac1 = state.Register("ac1", size=8)
        self.add(self.ac1)
        self.hi1 = state.RegisterAlias("hi1", self.ac1, size=4, offset=0)
        self.add(self.hi1)
        self.lo1 = state.RegisterAlias("lo1", self.ac1, size=4, offset=4)
        self.add(self.lo1)
        self.ac2 = state.Register("ac2", size=8)
        self.add(self.ac2)
        self.hi2 = state.RegisterAlias("hi2", self.ac2, size=4, offset=0)
        self.add(self.hi2)
        self.lo2 = state.RegisterAlias("lo2", self.ac2, size=4, offset=4)
        self.add(self.lo2)
        self.ac3 = state.Register("ac3", size=8)
        self.add(self.ac3)
        self.hi3 = state.RegisterAlias("hi3", self.ac3, size=4, offset=0)
        self.add(self.hi3)
        self.lo3 = state.RegisterAlias("lo3", self.ac3, size=4, offset=4)
        self.add(self.lo3)
        # TODO: MIPS has a boatload of extensions with their own registers.
        # There isn't a clean join between Sleigh, Unicorn, and MIPS docs.
