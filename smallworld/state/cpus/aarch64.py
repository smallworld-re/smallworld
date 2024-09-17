import typing

from ... import platforms
from .. import state
from . import cpu


class AArch64CPUState(cpu.CPU):
    """Auto-generated CPU state for aarch64:v8a:little

    Generated from Pcode language AARCH64:LE:64:v8A,
    and Unicorn package unicorn.arm64_const
    """

    # Special registers:
    # x29: frame pointer
    # x30: link register
    # x31: stack pointer or zero, depending on instruction
    _GENERAL_PURPOSE_REGS = [f"x{i}" for i in range(0, 29)]

    def get_general_purpose_registers(self) -> typing.List[str]:
        return self._GENERAL_PURPOSE_REGS

    @classmethod
    def get_platform(cls) -> platforms.Platform:
        return platforms.Platform(
            platforms.Architecture.AARCH64, platforms.Byteorder.LITTLE
        )

    def __init__(self):
        # *** General Purpose Registers ***
        self.x0 = state.Register("x0", size=8)
        self.w0 = state.RegisterAlias("w0", self.x0, size=4, offset=0)
        self.x1 = state.Register("x1", size=8)
        self.w1 = state.RegisterAlias("w1", self.x1, size=4, offset=0)
        self.x2 = state.Register("x2", size=8)
        self.w2 = state.RegisterAlias("w2", self.x2, size=4, offset=0)
        self.x3 = state.Register("x3", size=8)
        self.w3 = state.RegisterAlias("w3", self.x3, size=4, offset=0)
        self.x4 = state.Register("x4", size=8)
        self.w4 = state.RegisterAlias("w4", self.x4, size=4, offset=0)
        self.x5 = state.Register("x5", size=8)
        self.w5 = state.RegisterAlias("w5", self.x5, size=4, offset=0)
        self.x6 = state.Register("x6", size=8)
        self.w6 = state.RegisterAlias("w6", self.x6, size=4, offset=0)
        self.x7 = state.Register("x7", size=8)
        self.w7 = state.RegisterAlias("w7", self.x7, size=4, offset=0)
        self.x8 = state.Register("x8", size=8)
        self.w8 = state.RegisterAlias("w8", self.x8, size=4, offset=0)
        self.x9 = state.Register("x9", size=8)
        self.w9 = state.RegisterAlias("w9", self.x9, size=4, offset=0)
        self.x10 = state.Register("x10", size=8)
        self.w10 = state.RegisterAlias("w10", self.x10, size=4, offset=0)
        self.x11 = state.Register("x11", size=8)
        self.w11 = state.RegisterAlias("w11", self.x11, size=4, offset=0)
        self.x12 = state.Register("x12", size=8)
        self.w12 = state.RegisterAlias("w12", self.x12, size=4, offset=0)
        self.x13 = state.Register("x13", size=8)
        self.w13 = state.RegisterAlias("w13", self.x13, size=4, offset=0)
        self.x14 = state.Register("x14", size=8)
        self.w14 = state.RegisterAlias("w14", self.x14, size=4, offset=0)
        self.x15 = state.Register("x15", size=8)
        self.w15 = state.RegisterAlias("w15", self.x15, size=4, offset=0)
        self.x16 = state.Register("x16", size=8)
        self.w16 = state.RegisterAlias("w16", self.x16, size=4, offset=0)
        self.x17 = state.Register("x17", size=8)
        self.w17 = state.RegisterAlias("w17", self.x17, size=4, offset=0)
        self.x18 = state.Register("x18", size=8)
        self.w18 = state.RegisterAlias("w18", self.x18, size=4, offset=0)
        self.x19 = state.Register("x19", size=8)
        self.w19 = state.RegisterAlias("w19", self.x19, size=4, offset=0)
        self.x20 = state.Register("x20", size=8)
        self.w20 = state.RegisterAlias("w20", self.x20, size=4, offset=0)
        self.x21 = state.Register("x21", size=8)
        self.w21 = state.RegisterAlias("w21", self.x21, size=4, offset=0)
        self.x22 = state.Register("x22", size=8)
        self.w22 = state.RegisterAlias("w22", self.x22, size=4, offset=0)
        self.x23 = state.Register("x23", size=8)
        self.w23 = state.RegisterAlias("w23", self.x23, size=4, offset=0)
        self.x24 = state.Register("x24", size=8)
        self.w24 = state.RegisterAlias("w24", self.x24, size=4, offset=0)
        self.x25 = state.Register("x25", size=8)
        self.w25 = state.RegisterAlias("w25", self.x25, size=4, offset=0)
        self.x26 = state.Register("x26", size=8)
        self.w26 = state.RegisterAlias("w26", self.x26, size=4, offset=0)
        self.x27 = state.Register("x27", size=8)
        self.w27 = state.RegisterAlias("w27", self.x27, size=4, offset=0)
        self.x28 = state.Register("x28", size=8)
        self.w28 = state.RegisterAlias("w28", self.x28, size=4, offset=0)
        self.x29 = state.Register("x29", size=8)
        self.w29 = state.RegisterAlias("w29", self.x29, size=4, offset=0)
        self.x30 = state.Register("x30", size=8)
        self.w30 = state.RegisterAlias("w30", self.x30, size=4, offset=0)

        # *** Special Registers ***
        # Program Counter
        self.pc = state.Register("pc", size=8)
        # Stack Pointer
        self.sp = state.Register("sp", size=8)
        self.wsp = state.RegisterAlias("wsp", self.sp, size=4, offset=0)
        # fp: Frame pointer; alias for x29
        self.fp = state.RegisterAlias("fp", self.x29, size=8, offset=0)
        # lr: Link register; alias for x30
        self.lr = state.RegisterAlias("lr", self.x30, size=8, offset=0)
        # Zero Register
        self.xzr = state.Register("xzr", size=8)
        self.wzr = state.RegisterAlias("wzr", self.xzr, size=4, offset=0)
        # sp_elX: Banked stack pointers for exception handlers
        self.sp_el0 = state.Register("sp_el0", size=8)
        self.sp_el1 = state.Register("sp_el1", size=8)
        self.sp_el2 = state.Register("sp_el2", size=8)
        self.sp_el3 = state.Register("sp_el3", size=8)

        # *** System Registers ***
        # NOTE: Here, the name indicates the lowest EL that can access the register.
        # NOTE: The Unicorn model is missing a boatload of other system control registers.

        # Condition code register
        self.fpcr = state.Register("fpcr", size=8)
        # Floating Point Status Register
        self.fpsr = state.Register("fpsr", size=8)
        # elr_elX: Banked Exception Link Registers for exception handlers.
        # TODO: Unicorn lists an "elr_el0", but the AArch64 docs don't...
        self.elr_el1 = state.Register("elr_el1", size=8)
        self.elr_el2 = state.Register("elr_el2", size=8)
        self.elr_el3 = state.Register("elr_el3", size=8)
        # esr_elX: Banked Exception Syndrome Registers for exception handlers.
        # TODO: Unicorn lists an "esr_el0", but the AArch64 docs don't...
        self.esr_el1 = state.Register("esr_el1", size=8)
        self.esr_el2 = state.Register("esr_el2", size=8)
        self.esr_el3 = state.Register("esr_el3", size=8)
        # far_elX: Banked Fault Address Registers for exception handlers.
        # TODO: Unicorn lists a "far_el0", but the AArch64 docs don't...
        self.far_el1 = state.Register("far_el1", size=8)
        self.far_el2 = state.Register("far_el2", size=8)
        self.far_el3 = state.Register("far_el3", size=8)
        # vbar_elX: Banked Vector Base Address Registers for exception handlers
        self.vbar_el1 = state.Register("vbar_el1", size=8)
        # NOTE: vbar_el0 and vbar_el1 are aliases for each other.
        # The Sleigh model only recognizes vbar_el1,
        # so it needs to be the "real" copy.
        self.vbar_el0 = state.RegisterAlias("vbar_el0", self.vbar_el1, size=8, offset=0)
        self.vbar_el2 = state.Register("vbar_el2", size=8)
        self.vbar_el3 = state.Register("vbar_el3", size=8)
        # Coprocessor Access Control Register
        self.cpacr_el1 = state.Register("cpacr_el1", size=8)
        # Memory Attribute Indirection Register
        # NOTE: There should be four of these.
        self.mair_el1 = state.Register("mair_el1", size=8)
        # Physical Address Register
        self.par_el1 = state.Register("par_el1", size=8)
        # Translation Table Zero Base Register
        self.ttbr0_el1 = state.Register("ttbr0_el1", size=8)
        # Translation Table One Base Register
        self.ttbr1_el1 = state.Register("ttbr1_el1", size=8)
        # Thread ID Register
        # NOTE: There should be four of these.
        self.tpidr_el0 = state.Register("tpidr_el0", size=8)
        self.tpidr_el1 = state.Register("tpidr_el1", size=8)
        # Userspace-visible Thread ID register
        self.tpidrro_el0 = state.Register("tpidrro_el0", size=8)

        # Scalar floating point registers
        self.q0 = state.Register("q0", size=16)
        self.d0 = state.RegisterAlias("d0", self.q0, size=8, offset=0)
        self.s0 = state.RegisterAlias("s0", self.q0, size=4, offset=0)
        self.h0 = state.RegisterAlias("h0", self.q0, size=2, offset=0)
        self.b0 = state.RegisterAlias("b0", self.q0, size=1, offset=0)
        self.q1 = state.Register("q1", size=16)
        self.d1 = state.RegisterAlias("d1", self.q1, size=8, offset=0)
        self.s1 = state.RegisterAlias("s1", self.q1, size=4, offset=0)
        self.h1 = state.RegisterAlias("h1", self.q1, size=2, offset=0)
        self.b1 = state.RegisterAlias("b1", self.q1, size=1, offset=0)
        self.q2 = state.Register("q2", size=16)
        self.d2 = state.RegisterAlias("d2", self.q2, size=8, offset=0)
        self.s2 = state.RegisterAlias("s2", self.q2, size=4, offset=0)
        self.h2 = state.RegisterAlias("h2", self.q2, size=2, offset=0)
        self.b2 = state.RegisterAlias("b2", self.q2, size=1, offset=0)
        self.q3 = state.Register("q3", size=16)
        self.d3 = state.RegisterAlias("d3", self.q3, size=8, offset=0)
        self.s3 = state.RegisterAlias("s3", self.q3, size=4, offset=0)
        self.h3 = state.RegisterAlias("h3", self.q3, size=2, offset=0)
        self.b3 = state.RegisterAlias("b3", self.q3, size=1, offset=0)
        self.q4 = state.Register("q4", size=16)
        self.d4 = state.RegisterAlias("d4", self.q4, size=8, offset=0)
        self.s4 = state.RegisterAlias("s4", self.q4, size=4, offset=0)
        self.h4 = state.RegisterAlias("h4", self.q4, size=2, offset=0)
        self.b4 = state.RegisterAlias("b4", self.q4, size=1, offset=0)
        self.q5 = state.Register("q5", size=16)
        self.d5 = state.RegisterAlias("d5", self.q5, size=8, offset=0)
        self.s5 = state.RegisterAlias("s5", self.q5, size=4, offset=0)
        self.h5 = state.RegisterAlias("h5", self.q5, size=2, offset=0)
        self.b5 = state.RegisterAlias("b5", self.q5, size=1, offset=0)
        self.q6 = state.Register("q6", size=16)
        self.d6 = state.RegisterAlias("d6", self.q6, size=8, offset=0)
        self.s6 = state.RegisterAlias("s6", self.q6, size=4, offset=0)
        self.h6 = state.RegisterAlias("h6", self.q6, size=2, offset=0)
        self.b6 = state.RegisterAlias("b6", self.q6, size=1, offset=0)
        self.q7 = state.Register("q7", size=16)
        self.d7 = state.RegisterAlias("d7", self.q7, size=8, offset=0)
        self.s7 = state.RegisterAlias("s7", self.q7, size=4, offset=0)
        self.h7 = state.RegisterAlias("h7", self.q7, size=2, offset=0)
        self.b7 = state.RegisterAlias("b7", self.q7, size=1, offset=0)
        self.q8 = state.Register("q8", size=16)
        self.d8 = state.RegisterAlias("d8", self.q8, size=8, offset=0)
        self.s8 = state.RegisterAlias("s8", self.q8, size=4, offset=0)
        self.h8 = state.RegisterAlias("h8", self.q8, size=2, offset=0)
        self.b8 = state.RegisterAlias("b8", self.q8, size=1, offset=0)
        self.q9 = state.Register("q9", size=16)
        self.d9 = state.RegisterAlias("d9", self.q9, size=8, offset=0)
        self.s9 = state.RegisterAlias("s9", self.q9, size=4, offset=0)
        self.h9 = state.RegisterAlias("h9", self.q9, size=2, offset=0)
        self.b9 = state.RegisterAlias("b9", self.q9, size=1, offset=0)
        self.q10 = state.Register("q10", size=16)
        self.d10 = state.RegisterAlias("d10", self.q10, size=8, offset=0)
        self.s10 = state.RegisterAlias("s10", self.q10, size=4, offset=0)
        self.h10 = state.RegisterAlias("h10", self.q10, size=2, offset=0)
        self.b10 = state.RegisterAlias("b10", self.q10, size=1, offset=0)
        self.q11 = state.Register("q11", size=16)
        self.d11 = state.RegisterAlias("d11", self.q11, size=8, offset=0)
        self.s11 = state.RegisterAlias("s11", self.q11, size=4, offset=0)
        self.h11 = state.RegisterAlias("h11", self.q11, size=2, offset=0)
        self.b11 = state.RegisterAlias("b11", self.q11, size=1, offset=0)
        self.q12 = state.Register("q12", size=16)
        self.d12 = state.RegisterAlias("d12", self.q12, size=8, offset=0)
        self.s12 = state.RegisterAlias("s12", self.q12, size=4, offset=0)
        self.h12 = state.RegisterAlias("h12", self.q12, size=2, offset=0)
        self.b12 = state.RegisterAlias("b12", self.q12, size=1, offset=0)
        self.q13 = state.Register("q13", size=16)
        self.d13 = state.RegisterAlias("d13", self.q13, size=8, offset=0)
        self.s13 = state.RegisterAlias("s13", self.q13, size=4, offset=0)
        self.h13 = state.RegisterAlias("h13", self.q13, size=2, offset=0)
        self.b13 = state.RegisterAlias("b13", self.q13, size=1, offset=0)
        self.q14 = state.Register("q14", size=16)
        self.d14 = state.RegisterAlias("d14", self.q14, size=8, offset=0)
        self.s14 = state.RegisterAlias("s14", self.q14, size=4, offset=0)
        self.h14 = state.RegisterAlias("h14", self.q14, size=2, offset=0)
        self.b14 = state.RegisterAlias("b14", self.q14, size=1, offset=0)
        self.q15 = state.Register("q15", size=16)
        self.d15 = state.RegisterAlias("d15", self.q15, size=8, offset=0)
        self.s15 = state.RegisterAlias("s15", self.q15, size=4, offset=0)
        self.h15 = state.RegisterAlias("h15", self.q15, size=2, offset=0)
        self.b15 = state.RegisterAlias("b15", self.q15, size=1, offset=0)
        self.q16 = state.Register("q16", size=16)
        self.d16 = state.RegisterAlias("d16", self.q16, size=8, offset=0)
        self.s16 = state.RegisterAlias("s16", self.q16, size=4, offset=0)
        self.h16 = state.RegisterAlias("h16", self.q16, size=2, offset=0)
        self.b16 = state.RegisterAlias("b16", self.q16, size=1, offset=0)
        self.q17 = state.Register("q17", size=16)
        self.d17 = state.RegisterAlias("d17", self.q17, size=8, offset=0)
        self.s17 = state.RegisterAlias("s17", self.q17, size=4, offset=0)
        self.h17 = state.RegisterAlias("h17", self.q17, size=2, offset=0)
        self.b17 = state.RegisterAlias("b17", self.q17, size=1, offset=0)
        self.q18 = state.Register("q18", size=16)
        self.d18 = state.RegisterAlias("d18", self.q18, size=8, offset=0)
        self.s18 = state.RegisterAlias("s18", self.q18, size=4, offset=0)
        self.h18 = state.RegisterAlias("h18", self.q18, size=2, offset=0)
        self.b18 = state.RegisterAlias("b18", self.q18, size=1, offset=0)
        self.q19 = state.Register("q19", size=16)
        self.d19 = state.RegisterAlias("d19", self.q19, size=8, offset=0)
        self.s19 = state.RegisterAlias("s19", self.q19, size=4, offset=0)
        self.h19 = state.RegisterAlias("h19", self.q19, size=2, offset=0)
        self.b19 = state.RegisterAlias("b19", self.q19, size=1, offset=0)
        self.q20 = state.Register("q20", size=16)
        self.d20 = state.RegisterAlias("d20", self.q20, size=8, offset=0)
        self.s20 = state.RegisterAlias("s20", self.q20, size=4, offset=0)
        self.h20 = state.RegisterAlias("h20", self.q20, size=2, offset=0)
        self.b20 = state.RegisterAlias("b20", self.q20, size=1, offset=0)
        self.q21 = state.Register("q21", size=16)
        self.d21 = state.RegisterAlias("d21", self.q21, size=8, offset=0)
        self.s21 = state.RegisterAlias("s21", self.q21, size=4, offset=0)
        self.h21 = state.RegisterAlias("h21", self.q21, size=2, offset=0)
        self.b21 = state.RegisterAlias("b21", self.q21, size=1, offset=0)
        self.q22 = state.Register("q22", size=16)
        self.d22 = state.RegisterAlias("d22", self.q22, size=8, offset=0)
        self.s22 = state.RegisterAlias("s22", self.q22, size=4, offset=0)
        self.h22 = state.RegisterAlias("h22", self.q22, size=2, offset=0)
        self.b22 = state.RegisterAlias("b22", self.q22, size=1, offset=0)
        self.q23 = state.Register("q23", size=16)
        self.d23 = state.RegisterAlias("d23", self.q23, size=8, offset=0)
        self.s23 = state.RegisterAlias("s23", self.q23, size=4, offset=0)
        self.h23 = state.RegisterAlias("h23", self.q23, size=2, offset=0)
        self.b23 = state.RegisterAlias("b23", self.q23, size=1, offset=0)
        self.q24 = state.Register("q24", size=16)
        self.d24 = state.RegisterAlias("d24", self.q24, size=8, offset=0)
        self.s24 = state.RegisterAlias("s24", self.q24, size=4, offset=0)
        self.h24 = state.RegisterAlias("h24", self.q24, size=2, offset=0)
        self.b24 = state.RegisterAlias("b24", self.q24, size=1, offset=0)
        self.q25 = state.Register("q25", size=16)
        self.d25 = state.RegisterAlias("d25", self.q25, size=8, offset=0)
        self.s25 = state.RegisterAlias("s25", self.q25, size=4, offset=0)
        self.h25 = state.RegisterAlias("h25", self.q25, size=2, offset=0)
        self.b25 = state.RegisterAlias("b25", self.q25, size=1, offset=0)
        self.q26 = state.Register("q26", size=16)
        self.d26 = state.RegisterAlias("d26", self.q26, size=8, offset=0)
        self.s26 = state.RegisterAlias("s26", self.q26, size=4, offset=0)
        self.h26 = state.RegisterAlias("h26", self.q26, size=2, offset=0)
        self.b26 = state.RegisterAlias("b26", self.q26, size=1, offset=0)
        self.q27 = state.Register("q27", size=16)
        self.d27 = state.RegisterAlias("d27", self.q27, size=8, offset=0)
        self.s27 = state.RegisterAlias("s27", self.q27, size=4, offset=0)
        self.h27 = state.RegisterAlias("h27", self.q27, size=2, offset=0)
        self.b27 = state.RegisterAlias("b27", self.q27, size=1, offset=0)
        self.q28 = state.Register("q28", size=16)
        self.d28 = state.RegisterAlias("d28", self.q28, size=8, offset=0)
        self.s28 = state.RegisterAlias("s28", self.q28, size=4, offset=0)
        self.h28 = state.RegisterAlias("h28", self.q28, size=2, offset=0)
        self.b28 = state.RegisterAlias("b28", self.q28, size=1, offset=0)
        self.q29 = state.Register("q29", size=16)
        self.d29 = state.RegisterAlias("d29", self.q29, size=8, offset=0)
        self.s29 = state.RegisterAlias("s29", self.q29, size=4, offset=0)
        self.h29 = state.RegisterAlias("h29", self.q29, size=2, offset=0)
        self.b29 = state.RegisterAlias("b29", self.q29, size=1, offset=0)
        self.q30 = state.Register("q30", size=16)
        self.d30 = state.RegisterAlias("d30", self.q30, size=8, offset=0)
        self.s30 = state.RegisterAlias("s30", self.q30, size=4, offset=0)
        self.h30 = state.RegisterAlias("h30", self.q30, size=2, offset=0)
        self.b30 = state.RegisterAlias("b30", self.q30, size=1, offset=0)
        self.q31 = state.Register("q31", size=16)
        self.d31 = state.RegisterAlias("d31", self.q31, size=8, offset=0)
        self.s31 = state.RegisterAlias("s31", self.q31, size=4, offset=0)
        self.h31 = state.RegisterAlias("h31", self.q31, size=2, offset=0)
        self.b31 = state.RegisterAlias("b31", self.q31, size=1, offset=0)
        # *** Vector registers vX ***
        # I'm not sure how to model these.
