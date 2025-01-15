import typing

from ... import platforms, state
from . import cpu


class AArch64(cpu.CPU):
    """Auto-generated CPU state for aarch64:v8a:little

    Generated from Pcode language AARCH64:LE:64:v8A, and Unicorn package
    unicorn.arm64_const.
    """

    platform = platforms.Platform(
        platforms.Architecture.AARCH64, platforms.Byteorder.LITTLE
    )

    def get_general_purpose_registers(self) -> typing.List[str]:
        # Special registers:
        # x29: frame pointer
        # x30: link register
        # x31: stack pointer or zero, depending on instruction
        return [f"x{i}" for i in range(0, 29)]

    def __init__(self):
        super().__init__()
        # *** General Purpose Registers ***
        self.x0 = state.Register("x0", 8)
        self.add(self.x0)
        self.w0 = state.RegisterAlias("w0", self.x0, 4, 0)
        self.add(self.w0)
        self.x1 = state.Register("x1", 8)
        self.add(self.x1)
        self.w1 = state.RegisterAlias("w1", self.x1, 4, 0)
        self.add(self.w1)
        self.x2 = state.Register("x2", 8)
        self.add(self.x2)
        self.w2 = state.RegisterAlias("w2", self.x2, 4, 0)
        self.add(self.w2)
        self.x3 = state.Register("x3", 8)
        self.add(self.x3)
        self.w3 = state.RegisterAlias("w3", self.x3, 4, 0)
        self.add(self.w3)
        self.x4 = state.Register("x4", 8)
        self.add(self.x4)
        self.w4 = state.RegisterAlias("w4", self.x4, 4, 0)
        self.add(self.w4)
        self.x5 = state.Register("x5", 8)
        self.add(self.x5)
        self.w5 = state.RegisterAlias("w5", self.x5, 4, 0)
        self.add(self.w5)
        self.x6 = state.Register("x6", 8)
        self.add(self.x6)
        self.w6 = state.RegisterAlias("w6", self.x6, 4, 0)
        self.add(self.w6)
        self.x7 = state.Register("x7", 8)
        self.add(self.x7)
        self.w7 = state.RegisterAlias("w7", self.x7, 4, 0)
        self.add(self.w7)
        self.x8 = state.Register("x8", 8)
        self.add(self.x8)
        self.w8 = state.RegisterAlias("w8", self.x8, 4, 0)
        self.add(self.w8)
        self.x9 = state.Register("x9", 8)
        self.add(self.x9)
        self.w9 = state.RegisterAlias("w9", self.x9, 4, 0)
        self.add(self.w9)
        self.x10 = state.Register("x10", 8)
        self.add(self.x10)
        self.w10 = state.RegisterAlias("w10", self.x10, 4, 0)
        self.add(self.w10)
        self.x11 = state.Register("x11", 8)
        self.add(self.x11)
        self.w11 = state.RegisterAlias("w11", self.x10, 4, 0)
        self.add(self.w11)
        self.x12 = state.Register("x12", 8)
        self.add(self.x12)
        self.w12 = state.RegisterAlias("w12", self.x10, 4, 0)
        self.add(self.w12)
        self.x13 = state.Register("x13", 8)
        self.add(self.x13)
        self.w13 = state.RegisterAlias("w13", self.x13, 4, 0)
        self.add(self.w13)
        self.x14 = state.Register("x14", 8)
        self.add(self.x14)
        self.w14 = state.RegisterAlias("w14", self.x14, 4, 0)
        self.add(self.w14)
        self.x15 = state.Register("x15", 8)
        self.add(self.x15)
        self.w15 = state.RegisterAlias("w15", self.x15, 4, 0)
        self.add(self.w15)
        self.x16 = state.Register("x16", 8)
        self.add(self.x16)
        self.w16 = state.RegisterAlias("w16", self.x16, 4, 0)
        self.add(self.w16)
        self.x17 = state.Register("x17", 8)
        self.add(self.x17)
        self.w17 = state.RegisterAlias("w17", self.x17, 4, 0)
        self.add(self.w17)
        self.x18 = state.Register("x18", 8)
        self.add(self.x18)
        self.w18 = state.RegisterAlias("w18", self.x18, 4, 0)
        self.add(self.w18)
        self.x19 = state.Register("x19", 8)
        self.add(self.x19)
        self.w19 = state.RegisterAlias("w19", self.x19, 4, 0)
        self.add(self.w19)
        self.x20 = state.Register("x20", 8)
        self.add(self.x20)
        self.w20 = state.RegisterAlias("w20", self.x20, 4, 0)
        self.add(self.w20)
        self.x21 = state.Register("x21", 8)
        self.add(self.x21)
        self.w21 = state.RegisterAlias("w21", self.x20, 4, 0)
        self.add(self.w21)
        self.x22 = state.Register("x22", 8)
        self.add(self.x22)
        self.w22 = state.RegisterAlias("w22", self.x20, 4, 0)
        self.add(self.w22)
        self.x23 = state.Register("x23", 8)
        self.add(self.x23)
        self.w23 = state.RegisterAlias("w23", self.x23, 4, 0)
        self.add(self.w23)
        self.x24 = state.Register("x24", 8)
        self.add(self.x24)
        self.w24 = state.RegisterAlias("w24", self.x24, 4, 0)
        self.add(self.w24)
        self.x25 = state.Register("x25", 8)
        self.add(self.x25)
        self.w25 = state.RegisterAlias("w25", self.x25, 4, 0)
        self.add(self.w25)
        self.x26 = state.Register("x26", 8)
        self.add(self.x26)
        self.w26 = state.RegisterAlias("w26", self.x26, 4, 0)
        self.add(self.w26)
        self.x27 = state.Register("x27", 8)
        self.add(self.x27)
        self.w27 = state.RegisterAlias("w27", self.x27, 4, 0)
        self.add(self.w27)
        self.x28 = state.Register("x28", 8)
        self.add(self.x28)
        self.w28 = state.RegisterAlias("w28", self.x28, 4, 0)
        self.add(self.w28)
        self.x29 = state.Register("x29", 8)
        self.add(self.x29)
        self.w29 = state.RegisterAlias("w29", self.x29, 4, 0)
        self.add(self.w29)
        self.x30 = state.Register("x30", 8)
        self.add(self.x30)
        self.w30 = state.RegisterAlias("w30", self.x30, 4, 0)
        self.add(self.w30)
        # *** Program Counter ***
        self.pc = state.Register("pc", 8)
        self.add(self.pc)
        # *** Stack Pointer ***
        self.sp = state.Register("sp", 8)
        self.add(self.sp)
        self.wsp = state.RegisterAlias("wsp", self.sp, 4, 0)
        self.add(self.wsp)
        # *** Frame Pointer ***
        self.fp = state.RegisterAlias("fp", self.x29, 8, 0)
        self.add(self.fp)
        # *** Link Register ***
        self.lr = state.RegisterAlias("lr", self.x30, 8, 0)
        self.add(self.lr)
        # *** Zero Register ***
        self.xzr = state.FixedRegister("xzr", 8, 0)
        self.add(self.xzr)
        self.wzr = state.RegisterAlias("wzr", self.xzr, 4, 0)
        self.add(self.wzr)
        # *** System Control Registers ***
        # NOTE: "_elX" indicates that only exception level X or greater can access this register.
        # NOTE: This list is far from complete; it only covers what Unicorn supports
        # Condition Code Register
        self.fpcr = state.Register("fpcr", 8)
        self.add(self.fpcr)
        # Floating Point Status Register
        self.fpsr = state.Register("fpsr", 8)
        self.add(self.fpsr)
        # Banked stack pointers for exception handlers
        self.sp_el0 = state.Register("sp_el0", 8)
        self.add(self.sp_el0)
        self.sp_el1 = state.Register("sp_el1", 8)
        self.add(self.sp_el1)
        self.sp_el2 = state.Register("sp_el2", 8)
        self.add(self.sp_el2)
        self.sp_el3 = state.Register("sp_el3", 8)
        self.add(self.sp_el3)
        # Banked link registers for exception handlers
        # NOTE: Unicorn thinks there's an elr_el0; according to docs, it doesn't exist
        self.elr_el1 = state.Register("elr_el1", 8)
        self.add(self.elr_el1)
        self.elr_el2 = state.Register("elr_el2", 8)
        self.add(self.elr_el2)
        self.elr_el3 = state.Register("elr_el3", 8)
        self.add(self.elr_el3)
        # Banked exception syndrome registers for exception handlers
        # NOTE: Unicorn thinks there's a far_el0; according to docs, it doesn't exist
        self.far_el1 = state.Register("far_el1", 8)
        self.add(self.far_el1)
        self.far_el2 = state.Register("far_el2", 8)
        self.add(self.far_el2)
        self.far_el3 = state.Register("far_el3", 8)
        self.add(self.far_el3)
        # Banked vector base address registers for exception handlers
        # NOTE: vbar_el0 and vbar_el1 are aliases for each other.
        # Since vbar_el0 doesn't exist in angr, vbar_el1 has to be the "real" copy.
        self.vbar_el1 = state.Register("vbar_el1", 8)
        self.add(self.vbar_el1)
        self.vbar_el0 = state.RegisterAlias("vbar_el0", self.vbar_el1, 8, 0)
        self.add(self.vbar_el0)
        self.vbar_el2 = state.Register("vbar_el2", 8)
        self.add(self.vbar_el2)
        self.vbar_el3 = state.Register("vbar_el3", 8)
        self.add(self.vbar_el3)
        # Coprocessor access control register
        self.cpacr_el1 = state.Register("cpacr_el1", 8)
        self.add(self.cpacr_el1)
        # Memory Attribute Indirection Register
        self.mair_el1 = state.Register("mair_el1", 8)
        self.add(self.mair_el1)
        # Physical Address Register
        self.par_el1 = state.Register("par_el1", 8)
        self.add(self.par_el1)
        # Translation Table Zero Base Register
        self.ttbr0_el1 = state.Register("ttbr0_el1", 8)
        self.add(self.ttbr0_el1)
        # Translation Table One Base Register
        self.ttbr1_el1 = state.Register("ttbr1_el1", 8)
        self.add(self.ttbr1_el1)
        # Thread ID Register
        # NOTE: According to docs, there should be an el2 and el3 copy, too.
        self.tpidr_el0 = state.Register("tpidr_el0", 8)
        self.add(self.tpidr_el0)
        self.tpidr_el1 = state.Register("tpidr_el1", 8)
        self.add(self.tpidr_el1)
        # Userspace-visible Thread ID register
        self.tpidrro_el0 = state.Register("tpidrro_el0", 8)
        self.add(self.tpidrro_el0)
        # *** Floating Point Registers ***
        # Scalar Floating Point Registers
        self.q0 = state.Register("q0", 16)
        self.add(self.q0)
        self.d0 = state.RegisterAlias("d0", self.q0, 8, 0)
        self.add(self.d0)
        self.s0 = state.RegisterAlias("s0", self.q0, 4, 0)
        self.add(self.s0)
        self.h0 = state.RegisterAlias("h0", self.q0, 2, 0)
        self.add(self.h0)
        self.b0 = state.RegisterAlias("b0", self.q0, 1, 0)
        self.add(self.b0)
        self.q1 = state.Register("q1", 16)
        self.add(self.q1)
        self.d1 = state.RegisterAlias("d1", self.q1, 8, 0)
        self.add(self.d1)
        self.s1 = state.RegisterAlias("s1", self.q1, 4, 0)
        self.add(self.s1)
        self.h1 = state.RegisterAlias("h1", self.q1, 2, 0)
        self.add(self.h1)
        self.b1 = state.RegisterAlias("b1", self.q1, 1, 0)
        self.add(self.b1)
        self.q2 = state.Register("q2", 16)
        self.add(self.q2)
        self.d2 = state.RegisterAlias("d2", self.q2, 8, 0)
        self.add(self.d2)
        self.s2 = state.RegisterAlias("s2", self.q2, 4, 0)
        self.add(self.s2)
        self.h2 = state.RegisterAlias("h2", self.q2, 2, 0)
        self.add(self.h2)
        self.b2 = state.RegisterAlias("b2", self.q2, 1, 0)
        self.add(self.b2)
        self.q3 = state.Register("q3", 16)
        self.add(self.q3)
        self.d3 = state.RegisterAlias("d3", self.q3, 8, 0)
        self.add(self.d3)
        self.s3 = state.RegisterAlias("s3", self.q3, 4, 0)
        self.add(self.s3)
        self.h3 = state.RegisterAlias("h3", self.q3, 2, 0)
        self.add(self.h3)
        self.b3 = state.RegisterAlias("b3", self.q3, 1, 0)
        self.add(self.b3)
        self.q4 = state.Register("q4", 16)
        self.add(self.q4)
        self.d4 = state.RegisterAlias("d4", self.q4, 8, 0)
        self.add(self.d4)
        self.s4 = state.RegisterAlias("s4", self.q4, 4, 0)
        self.add(self.s4)
        self.h4 = state.RegisterAlias("h4", self.q4, 2, 0)
        self.add(self.h4)
        self.b4 = state.RegisterAlias("b4", self.q4, 1, 0)
        self.add(self.b4)
        self.q5 = state.Register("q5", 16)
        self.add(self.q5)
        self.d5 = state.RegisterAlias("d5", self.q5, 8, 0)
        self.add(self.d5)
        self.s5 = state.RegisterAlias("s5", self.q5, 4, 0)
        self.add(self.s5)
        self.h5 = state.RegisterAlias("h5", self.q5, 2, 0)
        self.add(self.h5)
        self.b5 = state.RegisterAlias("b5", self.q5, 1, 0)
        self.add(self.b5)
        self.q6 = state.Register("q6", 16)
        self.add(self.q6)
        self.d6 = state.RegisterAlias("d6", self.q6, 8, 0)
        self.add(self.d6)
        self.s6 = state.RegisterAlias("s6", self.q6, 4, 0)
        self.add(self.s6)
        self.h6 = state.RegisterAlias("h6", self.q6, 2, 0)
        self.add(self.h6)
        self.b6 = state.RegisterAlias("b6", self.q6, 1, 0)
        self.add(self.b6)
        self.q7 = state.Register("q7", 16)
        self.add(self.q7)
        self.d7 = state.RegisterAlias("d7", self.q7, 8, 0)
        self.add(self.d7)
        self.s7 = state.RegisterAlias("s7", self.q7, 4, 0)
        self.add(self.s7)
        self.h7 = state.RegisterAlias("h7", self.q7, 2, 0)
        self.add(self.h7)
        self.b7 = state.RegisterAlias("b7", self.q7, 1, 0)
        self.add(self.b7)
        self.q8 = state.Register("q8", 16)
        self.add(self.q8)
        self.d8 = state.RegisterAlias("d8", self.q8, 8, 0)
        self.add(self.d8)
        self.s8 = state.RegisterAlias("s8", self.q8, 4, 0)
        self.add(self.s8)
        self.h8 = state.RegisterAlias("h8", self.q8, 2, 0)
        self.add(self.h8)
        self.b8 = state.RegisterAlias("b8", self.q8, 1, 0)
        self.add(self.b8)
        self.q9 = state.Register("q9", 16)
        self.add(self.q9)
        self.d9 = state.RegisterAlias("d9", self.q9, 8, 0)
        self.add(self.d9)
        self.s9 = state.RegisterAlias("s9", self.q9, 4, 0)
        self.add(self.s9)
        self.h9 = state.RegisterAlias("h9", self.q9, 2, 0)
        self.add(self.h9)
        self.b9 = state.RegisterAlias("b9", self.q9, 1, 0)
        self.add(self.b9)
        self.q10 = state.Register("q10", 16)
        self.add(self.q10)
        self.d10 = state.RegisterAlias("d10", self.q10, 8, 0)
        self.add(self.d10)
        self.s10 = state.RegisterAlias("s10", self.q10, 4, 0)
        self.add(self.s10)
        self.h10 = state.RegisterAlias("h10", self.q10, 2, 0)
        self.add(self.h10)
        self.b10 = state.RegisterAlias("b10", self.q10, 1, 0)
        self.add(self.b10)
        self.q11 = state.Register("q11", 16)
        self.add(self.q11)
        self.d11 = state.RegisterAlias("d11", self.q11, 8, 0)
        self.add(self.d11)
        self.s11 = state.RegisterAlias("s11", self.q11, 4, 0)
        self.add(self.s11)
        self.h11 = state.RegisterAlias("h11", self.q11, 2, 0)
        self.add(self.h11)
        self.b11 = state.RegisterAlias("b11", self.q11, 1, 0)
        self.add(self.b11)
        self.q12 = state.Register("q12", 16)
        self.add(self.q12)
        self.d12 = state.RegisterAlias("d12", self.q12, 8, 0)
        self.add(self.d12)
        self.s12 = state.RegisterAlias("s12", self.q12, 4, 0)
        self.add(self.s12)
        self.h12 = state.RegisterAlias("h12", self.q12, 2, 0)
        self.add(self.h12)
        self.b12 = state.RegisterAlias("b12", self.q12, 1, 0)
        self.add(self.b12)
        self.q13 = state.Register("q13", 16)
        self.add(self.q13)
        self.d13 = state.RegisterAlias("d13", self.q13, 8, 0)
        self.add(self.d13)
        self.s13 = state.RegisterAlias("s13", self.q13, 4, 0)
        self.add(self.s13)
        self.h13 = state.RegisterAlias("h13", self.q13, 2, 0)
        self.add(self.h13)
        self.b13 = state.RegisterAlias("b13", self.q13, 1, 0)
        self.add(self.b13)
        self.q14 = state.Register("q14", 16)
        self.add(self.q14)
        self.d14 = state.RegisterAlias("d14", self.q14, 8, 0)
        self.add(self.d14)
        self.s14 = state.RegisterAlias("s14", self.q14, 4, 0)
        self.add(self.s14)
        self.h14 = state.RegisterAlias("h14", self.q14, 2, 0)
        self.add(self.h14)
        self.b14 = state.RegisterAlias("b14", self.q14, 1, 0)
        self.add(self.b14)
        self.q15 = state.Register("q15", 16)
        self.add(self.q15)
        self.d15 = state.RegisterAlias("d15", self.q15, 8, 0)
        self.add(self.d15)
        self.s15 = state.RegisterAlias("s15", self.q15, 4, 0)
        self.add(self.s15)
        self.h15 = state.RegisterAlias("h15", self.q15, 2, 0)
        self.add(self.h15)
        self.b15 = state.RegisterAlias("b15", self.q15, 1, 0)
        self.add(self.b15)
        self.q16 = state.Register("q16", 16)
        self.add(self.q16)
        self.d16 = state.RegisterAlias("d16", self.q16, 8, 0)
        self.add(self.d16)
        self.s16 = state.RegisterAlias("s16", self.q16, 4, 0)
        self.add(self.s16)
        self.h16 = state.RegisterAlias("h16", self.q16, 2, 0)
        self.add(self.h16)
        self.b16 = state.RegisterAlias("b16", self.q16, 1, 0)
        self.add(self.b16)
        self.q17 = state.Register("q17", 16)
        self.add(self.q17)
        self.d17 = state.RegisterAlias("d17", self.q17, 8, 0)
        self.add(self.d17)
        self.s17 = state.RegisterAlias("s17", self.q17, 4, 0)
        self.add(self.s17)
        self.h17 = state.RegisterAlias("h17", self.q17, 2, 0)
        self.add(self.h17)
        self.b17 = state.RegisterAlias("b17", self.q17, 1, 0)
        self.add(self.b17)
        self.q18 = state.Register("q18", 16)
        self.add(self.q18)
        self.d18 = state.RegisterAlias("d18", self.q18, 8, 0)
        self.add(self.d18)
        self.s18 = state.RegisterAlias("s18", self.q18, 4, 0)
        self.add(self.s18)
        self.h18 = state.RegisterAlias("h18", self.q18, 2, 0)
        self.add(self.h18)
        self.b18 = state.RegisterAlias("b18", self.q18, 1, 0)
        self.add(self.b18)
        self.q19 = state.Register("q19", 16)
        self.add(self.q19)
        self.d19 = state.RegisterAlias("d19", self.q19, 8, 0)
        self.add(self.d19)
        self.s19 = state.RegisterAlias("s19", self.q19, 4, 0)
        self.add(self.s19)
        self.h19 = state.RegisterAlias("h19", self.q19, 2, 0)
        self.add(self.h19)
        self.b19 = state.RegisterAlias("b19", self.q19, 1, 0)
        self.add(self.b19)
        self.q20 = state.Register("q20", 16)
        self.add(self.q20)
        self.d20 = state.RegisterAlias("d20", self.q20, 8, 0)
        self.add(self.d20)
        self.s20 = state.RegisterAlias("s20", self.q20, 4, 0)
        self.add(self.s20)
        self.h20 = state.RegisterAlias("h20", self.q20, 2, 0)
        self.add(self.h20)
        self.b20 = state.RegisterAlias("b20", self.q20, 1, 0)
        self.add(self.b20)
        self.q21 = state.Register("q21", 16)
        self.add(self.q21)
        self.d21 = state.RegisterAlias("d21", self.q21, 8, 0)
        self.add(self.d21)
        self.s21 = state.RegisterAlias("s21", self.q21, 4, 0)
        self.add(self.s21)
        self.h21 = state.RegisterAlias("h21", self.q21, 2, 0)
        self.add(self.h21)
        self.b21 = state.RegisterAlias("b21", self.q21, 1, 0)
        self.add(self.b21)
        self.q22 = state.Register("q22", 16)
        self.add(self.q22)
        self.d22 = state.RegisterAlias("d22", self.q22, 8, 0)
        self.add(self.d22)
        self.s22 = state.RegisterAlias("s22", self.q22, 4, 0)
        self.add(self.s22)
        self.h22 = state.RegisterAlias("h22", self.q22, 2, 0)
        self.add(self.h22)
        self.b22 = state.RegisterAlias("b22", self.q22, 1, 0)
        self.add(self.b22)
        self.q23 = state.Register("q23", 16)
        self.add(self.q23)
        self.d23 = state.RegisterAlias("d23", self.q23, 8, 0)
        self.add(self.d23)
        self.s23 = state.RegisterAlias("s23", self.q23, 4, 0)
        self.add(self.s23)
        self.h23 = state.RegisterAlias("h23", self.q23, 2, 0)
        self.add(self.h23)
        self.b23 = state.RegisterAlias("b23", self.q23, 1, 0)
        self.add(self.b23)
        self.q24 = state.Register("q24", 16)
        self.add(self.q24)
        self.d24 = state.RegisterAlias("d24", self.q24, 8, 0)
        self.add(self.d24)
        self.s24 = state.RegisterAlias("s24", self.q24, 4, 0)
        self.add(self.s24)
        self.h24 = state.RegisterAlias("h24", self.q24, 2, 0)
        self.add(self.h24)
        self.b24 = state.RegisterAlias("b24", self.q24, 1, 0)
        self.add(self.b24)
        self.q25 = state.Register("q25", 16)
        self.add(self.q25)
        self.d25 = state.RegisterAlias("d25", self.q25, 8, 0)
        self.add(self.d25)
        self.s25 = state.RegisterAlias("s25", self.q25, 4, 0)
        self.add(self.s25)
        self.h25 = state.RegisterAlias("h25", self.q25, 2, 0)
        self.add(self.h25)
        self.b25 = state.RegisterAlias("b25", self.q25, 1, 0)
        self.add(self.b25)
        self.q26 = state.Register("q26", 16)
        self.add(self.q26)
        self.d26 = state.RegisterAlias("d26", self.q26, 8, 0)
        self.add(self.d26)
        self.s26 = state.RegisterAlias("s26", self.q26, 4, 0)
        self.add(self.s26)
        self.h26 = state.RegisterAlias("h26", self.q26, 2, 0)
        self.add(self.h26)
        self.b26 = state.RegisterAlias("b26", self.q26, 1, 0)
        self.add(self.b26)
        self.q27 = state.Register("q27", 16)
        self.add(self.q27)
        self.d27 = state.RegisterAlias("d27", self.q27, 8, 0)
        self.add(self.d27)
        self.s27 = state.RegisterAlias("s27", self.q27, 4, 0)
        self.add(self.s27)
        self.h27 = state.RegisterAlias("h27", self.q27, 2, 0)
        self.add(self.h27)
        self.b27 = state.RegisterAlias("b27", self.q27, 1, 0)
        self.add(self.b27)
        self.q28 = state.Register("q28", 16)
        self.add(self.q28)
        self.d28 = state.RegisterAlias("d28", self.q28, 8, 0)
        self.add(self.d28)
        self.s28 = state.RegisterAlias("s28", self.q28, 4, 0)
        self.add(self.s28)
        self.h28 = state.RegisterAlias("h28", self.q28, 2, 0)
        self.add(self.h28)
        self.b28 = state.RegisterAlias("b28", self.q28, 1, 0)
        self.add(self.b28)
        self.q29 = state.Register("q29", 16)
        self.add(self.q29)
        self.d29 = state.RegisterAlias("d29", self.q29, 8, 0)
        self.add(self.d29)
        self.s29 = state.RegisterAlias("s29", self.q29, 4, 0)
        self.add(self.s29)
        self.h29 = state.RegisterAlias("h29", self.q29, 2, 0)
        self.add(self.h29)
        self.b29 = state.RegisterAlias("b29", self.q29, 1, 0)
        self.add(self.b29)
        self.q30 = state.Register("q30", 16)
        self.add(self.q30)
        self.d30 = state.RegisterAlias("d30", self.q30, 8, 0)
        self.add(self.d30)
        self.s30 = state.RegisterAlias("s30", self.q30, 4, 0)
        self.add(self.s30)
        self.h30 = state.RegisterAlias("h30", self.q30, 2, 0)
        self.add(self.h30)
        self.b30 = state.RegisterAlias("b30", self.q30, 1, 0)
        self.add(self.b30)
        self.q31 = state.Register("q31", 16)
        self.add(self.q31)
        self.d31 = state.RegisterAlias("d31", self.q31, 8, 0)
        self.add(self.d31)
        self.s31 = state.RegisterAlias("s31", self.q31, 4, 0)
        self.add(self.s31)
        self.h31 = state.RegisterAlias("h31", self.q31, 2, 0)
        self.add(self.h31)
        self.b31 = state.RegisterAlias("b31", self.q31, 1, 0)
        self.add(self.b31)
        # Vector registers
        # TODO: Figure out how to model these
