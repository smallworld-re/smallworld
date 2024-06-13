from ..state import CPU, Register, RegisterAlias


class MIPSBECPUState(CPU):
    """Auto-generated CPU state for mips:mips32:big

    Generated from Pcode language MIPS:BE:32:default,
    and Unicorn package unicorn.mips_const
    """

    arch = "mips"
    mode = "mips32"
    endian = "big"

    # Excluded registers:
    # - zero: Hard-wired to zero
    # - at: Reserved for assembler
    # - kX: Reserved for kernel; used as general in some ABIs
    # - fX: Floating-point registers
    # - acX: Accumulator registers
    GENERAL_PURPOSE_REGS = [
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

    def __init__(self):
        # NOTE: MIPS registers have both a name and a number.

        # *** General-Purpose Registers ***
        # Assembler-Temporary Register
        self.at = Register("at", width=4)
        self._1 = RegisterAlias("1", self.at, width=4, offset=0)
        # Return Value Registers
        self.v0 = Register("v0", width=4)
        self._2 = RegisterAlias("2", self.v0, width=4, offset=0)
        self.v1 = Register("v1", width=4)
        self._3 = RegisterAlias("3", self.v1, width=4, offset=0)
        # Argument Registers
        self.a0 = Register("a0", width=4)
        self._4 = RegisterAlias("4", self.a0, width=4, offset=0)
        self.a1 = Register("a1", width=4)
        self._5 = RegisterAlias("5", self.a1, width=4, offset=0)
        self.a2 = Register("a2", width=4)
        self._6 = RegisterAlias("6", self.a2, width=4, offset=0)
        self.a3 = Register("a3", width=4)
        self._7 = RegisterAlias("7", self.a3, width=4, offset=0)
        # Temporary Registers
        self.t0 = Register("t0", width=4)
        self._8 = RegisterAlias("8", self.t0, width=4, offset=0)
        self.t1 = Register("t1", width=4)
        self._9 = RegisterAlias("9", self.t1, width=4, offset=0)
        self.t2 = Register("t2", width=4)
        self._10 = RegisterAlias("10", self.t2, width=4, offset=0)
        self.t3 = Register("t3", width=4)
        self._11 = RegisterAlias("11", self.t3, width=4, offset=0)
        self.t4 = Register("t4", width=4)
        self._12 = RegisterAlias("12", self.t4, width=4, offset=0)
        self.t5 = Register("t5", width=4)
        self._13 = RegisterAlias("13", self.t5, width=4, offset=0)
        self.t6 = Register("t6", width=4)
        self._14 = RegisterAlias("14", self.t6, width=4, offset=0)
        self.t7 = Register("t7", width=4)
        self._15 = RegisterAlias("15", self.t7, width=4, offset=0)
        # NOTE: These numbers aren't out of order.
        # t8 and t9 are later in the register file than t0 - t7.
        self.t8 = Register("t8", width=4)
        self._24 = RegisterAlias("24", self.t8, width=4, offset=0)
        self.t9 = Register("t9", width=4)
        self._25 = RegisterAlias("25", self.t9, width=4, offset=0)
        # Saved Registers
        self.s0 = Register("s0", width=4)
        self._16 = RegisterAlias("16", self.s0, width=4, offset=0)
        self.s1 = Register("s1", width=4)
        self._17 = RegisterAlias("17", self.s1, width=4, offset=0)
        self.s2 = Register("s2", width=4)
        self._18 = RegisterAlias("18", self.s2, width=4, offset=0)
        self.s3 = Register("s3", width=4)
        self._19 = RegisterAlias("19", self.s3, width=4, offset=0)
        self.s4 = Register("s4", width=4)
        self._20 = RegisterAlias("20", self.s4, width=4, offset=0)
        self.s5 = Register("s5", width=4)
        self._21 = RegisterAlias("21", self.s5, width=4, offset=0)
        self.s6 = Register("s6", width=4)
        self._22 = RegisterAlias("22", self.s6, width=4, offset=0)
        self.s7 = Register("s7", width=4)
        self._23 = RegisterAlias("23", self.s7, width=4, offset=0)
        # NOTE: Register #30 was originally the Frame Pointer.
        # It's been re-aliased as s8, since many ABIs don't use the frame pointer.
        # Unicorn and Sleigh prefer to use the alias s8,
        # so it should be the base register.
        self.s8 = Register("s8", width=4)
        self.fp = RegisterAlias("fp", self.s8, width=4, offset=0)
        self._30 = RegisterAlias("30", self.s8, width=4, offset=0)
        # Kernel-reserved Registers
        self.k0 = Register("k0", width=4)
        self._26 = RegisterAlias("26", self.k0, width=4, offset=0)
        self.k1 = Register("k1", width=4)
        self._27 = RegisterAlias("27", self.k1, width=4, offset=0)
        # *** Pointer Registers ***
        # Zero register
        self.zero = Register("zero", width=4)
        self._0 = RegisterAlias("0", self.zero, width=4, offset=0)
        # Global Offset Pointer
        self.gp = Register("gp", width=4)
        self._28 = RegisterAlias("28", self.gp, width=4, offset=0)
        # Stack Pointer
        self.sp = Register("sp", width=4)
        self._29 = RegisterAlias("29", self.sp, width=4, offset=0)
        # Return Address
        self.ra = Register("ra", width=4)
        self._31 = RegisterAlias("31", self.ra, width=4, offset=0)
        # Program Counter
        self.pc = Register("pc", width=4)
        # Floating Point Registers
        self.f0 = Register("f0", width=4)
        self.f1 = Register("f1", width=4)
        self.f2 = Register("f2", width=4)
        self.f3 = Register("f3", width=4)
        self.f4 = Register("f4", width=4)
        self.f5 = Register("f5", width=4)
        self.f6 = Register("f6", width=4)
        self.f7 = Register("f7", width=4)
        self.f8 = Register("f8", width=4)
        self.f9 = Register("f9", width=4)
        self.f10 = Register("f10", width=4)
        self.f11 = Register("f11", width=4)
        self.f12 = Register("f12", width=4)
        self.f13 = Register("f13", width=4)
        self.f14 = Register("f14", width=4)
        self.f15 = Register("f15", width=4)
        self.f16 = Register("f16", width=4)
        self.f17 = Register("f17", width=4)
        self.f18 = Register("f18", width=4)
        self.f19 = Register("f19", width=4)
        self.f20 = Register("f20", width=4)
        self.f21 = Register("f21", width=4)
        self.f22 = Register("f22", width=4)
        self.f23 = Register("f23", width=4)
        self.f24 = Register("f24", width=4)
        self.f25 = Register("f25", width=4)
        self.f26 = Register("f26", width=4)
        self.f27 = Register("f27", width=4)
        self.f28 = Register("f28", width=4)
        self.f29 = Register("f29", width=4)
        self.f30 = Register("f30", width=4)
        self.f31 = Register("f31", width=4)
        # *** Floating Point Control Registers ***
        # NOTE: These are taken from Sleigh, and the MIPS docs.
        # Unicorn doesn't use these names, and has a different number of registers.
        self.fir = Register("fir", width=4)
        self.fcsr = Register("fcsr", width=4)
        self.fexr = Register("fexr", width=4)
        self.fenr = Register("fenr", width=4)
        self.fccr = Register("fccr", width=4)
        # *** Accumulator Registers ***
        # MIPS uses these to implement 64-bit results
        # from 32-bit multiplication, amongst others.
        self.ac0 = Register("ac0", width=8)
        # NOTE: Be careful: there is also a 'hi' and 'lo' register;
        # they do different things.
        self.hi0 = RegisterAlias("hi0", self.ac0, width=4, offset=0)
        self.lo0 = RegisterAlias("lo0", self.ac0, width=4, offset=4)
        self.ac1 = Register("ac1", width=8)
        self.hi1 = RegisterAlias("hi1", self.ac1, width=4, offset=0)
        self.lo1 = RegisterAlias("lo1", self.ac1, width=4, offset=4)
        self.ac2 = Register("ac2", width=8)
        self.hi2 = RegisterAlias("hi2", self.ac2, width=4, offset=0)
        self.lo2 = RegisterAlias("lo2", self.ac2, width=4, offset=4)
        self.ac3 = Register("ac3", width=8)
        self.hi3 = RegisterAlias("hi3", self.ac3, width=4, offset=0)
        self.lo3 = RegisterAlias("lo3", self.ac3, width=4, offset=4)
        # TODO: MIPS has a boatload of extensions with their own registers.
        # There isn't a clean join between Sleigh, Unicorn, and MIPS docs.


class MIPSELCPUState(CPU):
    """Auto-generated CPU state for mips:mips32:little

    Generated from Pcode language MIPS:LE:32:default,
    and Unicorn package unicorn.mips_const
    """

    arch = "mips"
    mode = "mips32"
    endian = "little"

    # Excluded registers:
    # - zero: Hard-wired to zero
    # - at: Reserved for assembler
    # - kX: Reserved for kernel; used as general in some ABIs
    # - fX: Floating-point registers
    # - acX: Accumulator registers
    GENERAL_PURPOSE_REGS = [
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

    def __init__(self):
        # NOTE: MIPS registers have both a name and a number.

        # *** General-Purpose Registers ***
        # Assembler-Temporary Register
        self.at = Register("at", width=4)
        self._1 = RegisterAlias("1", self.at, width=4, offset=0)
        # Return Value Registers
        self.v0 = Register("v0", width=4)
        self._2 = RegisterAlias("2", self.v0, width=4, offset=0)
        self.v1 = Register("v1", width=4)
        self._3 = RegisterAlias("3", self.v1, width=4, offset=0)
        # Argument Registers
        self.a0 = Register("a0", width=4)
        self._4 = RegisterAlias("4", self.a0, width=4, offset=0)
        self.a1 = Register("a1", width=4)
        self._5 = RegisterAlias("5", self.a1, width=4, offset=0)
        self.a2 = Register("a2", width=4)
        self._6 = RegisterAlias("6", self.a2, width=4, offset=0)
        self.a3 = Register("a3", width=4)
        self._7 = RegisterAlias("7", self.a3, width=4, offset=0)
        # Temporary Registers
        self.t0 = Register("t0", width=4)
        self._8 = RegisterAlias("8", self.t0, width=4, offset=0)
        self.t1 = Register("t1", width=4)
        self._9 = RegisterAlias("9", self.t1, width=4, offset=0)
        self.t2 = Register("t2", width=4)
        self._10 = RegisterAlias("10", self.t2, width=4, offset=0)
        self.t3 = Register("t3", width=4)
        self._11 = RegisterAlias("11", self.t3, width=4, offset=0)
        self.t4 = Register("t4", width=4)
        self._12 = RegisterAlias("12", self.t4, width=4, offset=0)
        self.t5 = Register("t5", width=4)
        self._13 = RegisterAlias("13", self.t5, width=4, offset=0)
        self.t6 = Register("t6", width=4)
        self._14 = RegisterAlias("14", self.t6, width=4, offset=0)
        self.t7 = Register("t7", width=4)
        self._15 = RegisterAlias("15", self.t7, width=4, offset=0)
        # NOTE: These numbers aren't out of order.
        # t8 and t9 are later in the register file than t0 - t7.
        self.t8 = Register("t8", width=4)
        self._24 = RegisterAlias("24", self.t8, width=4, offset=0)
        self.t9 = Register("t9", width=4)
        self._25 = RegisterAlias("25", self.t9, width=4, offset=0)
        # Saved Registers
        self.s0 = Register("s0", width=4)
        self._16 = RegisterAlias("16", self.s0, width=4, offset=0)
        self.s1 = Register("s1", width=4)
        self._17 = RegisterAlias("17", self.s1, width=4, offset=0)
        self.s2 = Register("s2", width=4)
        self._18 = RegisterAlias("18", self.s2, width=4, offset=0)
        self.s3 = Register("s3", width=4)
        self._19 = RegisterAlias("19", self.s3, width=4, offset=0)
        self.s4 = Register("s4", width=4)
        self._20 = RegisterAlias("20", self.s4, width=4, offset=0)
        self.s5 = Register("s5", width=4)
        self._21 = RegisterAlias("21", self.s5, width=4, offset=0)
        self.s6 = Register("s6", width=4)
        self._22 = RegisterAlias("22", self.s6, width=4, offset=0)
        self.s7 = Register("s7", width=4)
        self._23 = RegisterAlias("23", self.s7, width=4, offset=0)
        # NOTE: Register #30 was originally the Frame Pointer.
        # It's been re-aliased as s8, since many ABIs don't use the frame pointer.
        # Unicorn and Sleigh prefer to use the alias s8,
        # so it should be the base register.
        self.s8 = Register("s8", width=4)
        self.fp = RegisterAlias("fp", self.s8, width=4, offset=0)
        self._30 = RegisterAlias("30", self.s8, width=4, offset=0)
        # Kernel-reserved Registers
        self.k0 = Register("k0", width=4)
        self._26 = RegisterAlias("26", self.k0, width=4, offset=0)
        self.k1 = Register("k1", width=4)
        self._27 = RegisterAlias("27", self.k1, width=4, offset=0)
        # *** Pointer Registers ***
        # Zero register
        self.zero = Register("zero", width=4)
        self._0 = RegisterAlias("0", self.zero, width=4, offset=0)
        # Global Offset Pointer
        self.gp = Register("gp", width=4)
        self._28 = RegisterAlias("28", self.gp, width=4, offset=0)
        # Stack Pointer
        self.sp = Register("sp", width=4)
        self._29 = RegisterAlias("29", self.sp, width=4, offset=0)
        # Return Address
        self.ra = Register("ra", width=4)
        self._31 = RegisterAlias("31", self.ra, width=4, offset=0)
        # Program Counter
        self.pc = Register("pc", width=4)
        # Floating Point Registers
        self.f0 = Register("f0", width=4)
        self.f1 = Register("f1", width=4)
        self.f2 = Register("f2", width=4)
        self.f3 = Register("f3", width=4)
        self.f4 = Register("f4", width=4)
        self.f5 = Register("f5", width=4)
        self.f6 = Register("f6", width=4)
        self.f7 = Register("f7", width=4)
        self.f8 = Register("f8", width=4)
        self.f9 = Register("f9", width=4)
        self.f10 = Register("f10", width=4)
        self.f11 = Register("f11", width=4)
        self.f12 = Register("f12", width=4)
        self.f13 = Register("f13", width=4)
        self.f14 = Register("f14", width=4)
        self.f15 = Register("f15", width=4)
        self.f16 = Register("f16", width=4)
        self.f17 = Register("f17", width=4)
        self.f18 = Register("f18", width=4)
        self.f19 = Register("f19", width=4)
        self.f20 = Register("f20", width=4)
        self.f21 = Register("f21", width=4)
        self.f22 = Register("f22", width=4)
        self.f23 = Register("f23", width=4)
        self.f24 = Register("f24", width=4)
        self.f25 = Register("f25", width=4)
        self.f26 = Register("f26", width=4)
        self.f27 = Register("f27", width=4)
        self.f28 = Register("f28", width=4)
        self.f29 = Register("f29", width=4)
        self.f30 = Register("f30", width=4)
        self.f31 = Register("f31", width=4)
        # *** Floating Point Control Registers ***
        # NOTE: These are taken from Sleigh, and the MIPS docs.
        # Unicorn doesn't use these names, and has a different number of registers.
        self.fir = Register("fir", width=4)
        self.fcsr = Register("fcsr", width=4)
        self.fexr = Register("fexr", width=4)
        self.fenr = Register("fenr", width=4)
        self.fccr = Register("fccr", width=4)
        # *** Accumulator Registers ***
        # MIPS uses these to implement 64-bit results
        # from 32-bit multiplication, amongst others.
        self.ac0 = Register("ac0", width=8)
        self.lo = RegisterAlias("lo0", self.ac0, width=4, offset=0)
        self.hi = RegisterAlias("hi0", self.ac0, width=4, offset=4)
        self.ac1 = Register("ac1", width=8)
        self.lo1 = RegisterAlias("lo1", self.ac1, width=4, offset=0)
        self.hi1 = RegisterAlias("hi1", self.ac1, width=4, offset=4)
        self.ac2 = Register("ac2", width=8)
        self.lo2 = RegisterAlias("lo2", self.ac2, width=4, offset=0)
        self.hi2 = RegisterAlias("hi2", self.ac2, width=4, offset=4)
        self.ac3 = Register("ac3", width=8)
        self.lo3 = RegisterAlias("lo3", self.ac3, width=4, offset=0)
        self.hi3 = RegisterAlias("hi3", self.ac3, width=4, offset=4)
        # TODO: MIPS has a boatload of extensions with their own registers.
        # There isn't a clean join between Sleigh, Unicorn, and MIPS docs.
