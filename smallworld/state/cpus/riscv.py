import typing

from ... import platforms, state
from . import cpu


class RISCV64(cpu.CPU):
    """CPU state for riscv64"""

    platform = platforms.Platform(
        platforms.Architecture.RISCV64, platforms.Byteorder.LITTLE
    )

    def get_general_purpose_registers(self) -> typing.List[str]:
        # - x0 is wired to zero
        # - x1 is the link register
        # - x2 is the stack pointer
        # - x3 is the global pointer
        # - x4 is the thread pointer
        return [f"x{i}" for i in range(5, 32)]

    def __init__(self):
        super().__init__()
        # *** General-Purpose Registers ***
        # x0 is wired to 0, and aliased as "zero"
        self.x0 = state.FixedRegister("x0", 8, 0)
        self.add(self.x0)
        self.zero = state.RegisterAlias("zero", self.x0, 8, 0)
        self.add(self.zero)
        # x1 acts as the link register
        # NOTE: ra is the official name; lr might be an angr invention.
        self.x1 = state.Register("x1", 8)
        self.add(self.x1)
        self.ra = state.RegisterAlias("ra", self.x1, 8, 0)
        self.add(self.ra)
        # x2 acts as the stack pointer
        self.x2 = state.Register("x2", 8)
        self.add(self.x2)
        self.sp = state.RegisterAlias("sp", self.x2, 8, 0)
        self.add(self.sp)
        # x3 acts as the global pointer
        self.x3 = state.Register("x3", 8)
        self.add(self.x3)
        self.gp = state.RegisterAlias("gp", self.x3, 8, 0)
        self.add(self.gp)
        # x4 acts as the thread pointer
        self.x4 = state.Register("x4", 8)
        self.add(self.x4)
        self.tp = state.RegisterAlias("tp", self.x4, 8, 0)
        self.add(self.tp)
        # x5 is a temporary register
        self.x5 = state.Register("x5", 8)
        self.add(self.x5)
        self.t0 = state.RegisterAlias("t0", self.x5, 8, 0)
        self.add(self.t0)
        # x6 is a temporary register
        self.x6 = state.Register("x6", 8)
        self.add(self.x6)
        self.t1 = state.RegisterAlias("t1", self.x6, 8, 0)
        self.add(self.t1)
        # x7 is a temporary register
        self.x7 = state.Register("x7", 8)
        self.add(self.x7)
        self.t2 = state.RegisterAlias("t2", self.x7, 8, 0)
        self.add(self.t2)
        # x8 is a callee-saved register
        self.x8 = state.Register("x8", 8)
        self.add(self.x8)
        self.s0 = state.RegisterAlias("s0", self.x8, 8, 0)
        self.add(self.x8)
        # x9 is a callee-saved register
        self.x9 = state.Register("x9", 8)
        self.add(self.x9)
        self.s1 = state.RegisterAlias("s1", self.x9, 8, 0)
        self.add(self.s1)
        # x10 is argument 0
        self.x10 = state.Register("x10", 8)
        self.add(self.x10)
        self.a0 = state.RegisterAlias("a0", self.x10, 8, 0)
        self.add(self.a0)
        # x11 is argument 1
        self.x11 = state.Register("x11", 8)
        self.add(self.x11)
        self.a1 = state.RegisterAlias("a1", self.x11, 8, 0)
        self.add(self.a1)
        # x12 is argument 2
        self.x12 = state.Register("x12", 8)
        self.add(self.x12)
        self.a2 = state.RegisterAlias("a2", self.x12, 8, 0)
        self.add(self.a2)
        # x13 is argument 3
        self.x13 = state.Register("x13", 8)
        self.add(self.x13)
        self.a3 = state.RegisterAlias("a3", self.x13, 8, 0)
        self.add(self.a3)
        # x14 is argument 4
        self.x14 = state.Register("x14", 8)
        self.add(self.x14)
        self.a4 = state.RegisterAlias("a4", self.x14, 8, 0)
        self.add(self.a4)
        # x15 is argument 5
        self.x15 = state.Register("x15", 8)
        self.add(self.x15)
        self.a5 = state.RegisterAlias("a5", self.x15, 8, 0)
        self.add(self.a5)
        # x16 is argument 6
        self.x16 = state.Register("x16", 8)
        self.add(self.x16)
        self.a6 = state.RegisterAlias("a6", self.x16, 8, 0)
        self.add(self.a6)
        # x17 is argument 7
        self.x17 = state.Register("x17", 8)
        self.add(self.x17)
        self.a7 = state.RegisterAlias("a7", self.x17, 8, 0)
        self.add(self.a7)
        # x18 is a callee-saved register
        self.x18 = state.Register("x18", 8)
        self.add(self.x18)
        self.s2 = state.RegisterAlias("s2", self.x18, 8, 0)
        self.add(self.s2)
        # x19 is a callee-saved register
        self.x19 = state.Register("x19", 8)
        self.add(self.x19)
        self.s3 = state.RegisterAlias("s3", self.x19, 8, 0)
        self.add(self.s3)
        # x20 is a callee-saved register
        self.x20 = state.Register("x20", 8)
        self.add(self.x20)
        self.s4 = state.RegisterAlias("s4", self.x20, 8, 0)
        self.add(self.s4)
        # x21 is a callee-saved register
        self.x21 = state.Register("x21", 8)
        self.add(self.x21)
        self.s5 = state.RegisterAlias("s5", self.x21, 8, 0)
        self.add(self.s5)
        # x22 is a callee-saved register
        self.x22 = state.Register("x22", 8)
        self.add(self.x22)
        self.s6 = state.RegisterAlias("s6", self.x22, 8, 0)
        self.add(self.s6)
        # x23 is a callee-saved register
        self.x23 = state.Register("x23", 8)
        self.add(self.x23)
        self.s7 = state.RegisterAlias("s7", self.x23, 8, 0)
        self.add(self.s7)
        # x24 is a callee-saved register
        self.x24 = state.Register("x24", 8)
        self.add(self.x24)
        self.s8 = state.RegisterAlias("s8", self.x24, 8, 0)
        self.add(self.s8)
        # x25 is a callee-saved register
        self.x25 = state.Register("x25", 8)
        self.add(self.x25)
        self.s9 = state.RegisterAlias("s9", self.x25, 8, 0)
        self.add(self.s9)
        # x26 is a callee-saved register
        self.x26 = state.Register("x26", 8)
        self.add(self.x26)
        self.s10 = state.RegisterAlias("s10", self.x26, 8, 0)
        self.add(self.s10)
        # x27 is a callee-saved register
        self.x27 = state.Register("x27", 8)
        self.add(self.x27)
        self.s11 = state.RegisterAlias("s11", self.x27, 8, 0)
        self.add(self.s11)
        # x28 is a temporary register
        self.x28 = state.Register("x28", 8)
        self.add(self.x28)
        self.t3 = state.RegisterAlias("t3", self.x28, 8, 0)
        self.add(self.t3)
        # x29 is a temporary register
        self.x29 = state.Register("x29", 8)
        self.add(self.x29)
        self.t4 = state.RegisterAlias("t4", self.x29, 8, 0)
        self.add(self.t4)
        # x30 is a temporary register
        self.x30 = state.Register("x30", 8)
        self.add(self.x30)
        self.t5 = state.RegisterAlias("t5", self.x30, 8, 0)
        self.add(self.t5)
        # x31 is a temporary register
        self.x31 = state.Register("x31", 8)
        self.add(self.x31)
        self.t6 = state.RegisterAlias("t6", self.x31, 8, 0)
        self.add(self.t6)

        # *** Program Counter ***
        self.pc = state.Register("pc", 8)
        self.add(self.pc)

        # *** Floating-Point Registers ***
        # f0 is a temporary register
        self.f0 = state.Register("f0", 8)
        self.add(self.f0)
        self.ft0 = state.RegisterAlias("ft0", self.f0, 8, 0)
        self.add(self.ft0)
        # f1 is a temporary register
        self.f1 = state.Register("f1", 8)
        self.add(self.f1)
        self.ft1 = state.RegisterAlias("ft1", self.f1, 8, 0)
        self.add(self.ft1)
        # f2 is a temporary register
        self.f2 = state.Register("f2", 8)
        self.add(self.f2)
        self.ft2 = state.RegisterAlias("ft2", self.f2, 8, 0)
        self.add(self.ft2)
        # f3 is a temporary register
        self.f3 = state.Register("f3", 8)
        self.add(self.f3)
        self.ft3 = state.RegisterAlias("ft3", self.f3, 8, 0)
        self.add(self.ft3)
        # f4 is a temporary register
        self.f4 = state.Register("f4", 8)
        self.add(self.f4)
        self.ft4 = state.RegisterAlias("ft4", self.f4, 8, 0)
        self.add(self.ft4)
        # f5 is a temporary register
        self.f5 = state.Register("f5", 8)
        self.add(self.f5)
        self.ft5 = state.RegisterAlias("ft5", self.f5, 8, 0)
        self.add(self.ft5)
        # f6 is a temporary register
        self.f6 = state.Register("f6", 8)
        self.add(self.f6)
        self.ft6 = state.RegisterAlias("ft6", self.f6, 8, 0)
        self.add(self.ft6)
        # f7 is a temporary register
        self.f7 = state.Register("f7", 8)
        self.add(self.f7)
        self.ft7 = state.RegisterAlias("ft7", self.f7, 8, 0)
        self.add(self.ft7)
        # f8 is a callee saved register
        self.f8 = state.Register("f8", 8)
        self.add(self.f8)
        self.fs0 = state.RegisterAlias("fs0", self.f8, 8, 0)
        self.add(self.fs0)
        # f9 is a callee saved register
        self.f9 = state.Register("f9", 8)
        self.add(self.f9)
        self.fs1 = state.RegisterAlias("fs1", self.f9, 8, 0)
        self.add(self.fs1)
        # f10 is argument 0
        self.f10 = state.Register("f10", 8)
        self.add(self.f10)
        self.fa0 = state.RegisterAlias("fa0", self.f10, 8, 0)
        self.add(self.fa0)
        # f11 is argument 1
        self.f11 = state.Register("f11", 8)
        self.add(self.f11)
        self.fa1 = state.RegisterAlias("fa1", self.f11, 8, 0)
        self.add(self.fa1)
        # f12 is argument 2
        self.f12 = state.Register("f12", 8)
        self.add(self.f12)
        self.fa2 = state.RegisterAlias("fa2", self.f12, 8, 0)
        self.add(self.fa2)
        # f13 is argument 3
        self.f13 = state.Register("f13", 8)
        self.add(self.f13)
        self.fa3 = state.RegisterAlias("fa3", self.f13, 8, 0)
        self.add(self.fa3)
        # f14 is argument 4
        self.f14 = state.Register("f14", 8)
        self.add(self.f14)
        self.fa4 = state.RegisterAlias("fa4", self.f14, 8, 0)
        self.add(self.fa4)
        # f15 is argument 5
        self.f15 = state.Register("f15", 8)
        self.add(self.f15)
        self.fa5 = state.RegisterAlias("fa5", self.f15, 8, 0)
        self.add(self.fa5)
        # f16 is argument 6
        self.f16 = state.Register("f16", 8)
        self.add(self.f16)
        self.fa6 = state.RegisterAlias("fa6", self.f16, 8, 0)
        self.add(self.fa6)
        # f7 is argument 7
        self.f17 = state.Register("f17", 8)
        self.add(self.f17)
        self.fa7 = state.RegisterAlias("fa7", self.f17, 8, 0)
        self.add(self.fa7)
        # f18 is a callee-saved register
        self.f18 = state.Register("f18", 8)
        self.add(self.f18)
        self.fs2 = state.RegisterAlias("fs2", self.f18, 8, 0)
        self.add(self.fs2)
        # f19 is a callee-saved register
        self.f19 = state.Register("f19", 8)
        self.add(self.f19)
        self.fs3 = state.RegisterAlias("fs3", self.f19, 8, 0)
        self.add(self.fs3)
        # f20 is a callee-saved register
        self.f20 = state.Register("f20", 8)
        self.add(self.f20)
        self.fs4 = state.RegisterAlias("fs4", self.f20, 8, 0)
        self.add(self.fs4)
        # f21 is a callee-saved register
        self.f21 = state.Register("f21", 8)
        self.add(self.f21)
        self.fs5 = state.RegisterAlias("fs5", self.f21, 8, 0)
        self.add(self.fs5)
        # f22 is a callee-saved register
        self.f22 = state.Register("f22", 8)
        self.add(self.f22)
        self.fs6 = state.RegisterAlias("fs6", self.f22, 8, 0)
        self.add(self.fs6)
        # f23 is a callee-saved register
        self.f23 = state.Register("f23", 8)
        self.add(self.f23)
        self.fs7 = state.RegisterAlias("fs7", self.f23, 8, 0)
        self.add(self.fs7)
        # f24 is a callee-saved register
        self.f24 = state.Register("f24", 8)
        self.add(self.f24)
        self.fs8 = state.RegisterAlias("fs8", self.f24, 8, 0)
        self.add(self.fs8)
        # f25 is a callee-saved register
        self.f25 = state.Register("f25", 8)
        self.add(self.f25)
        self.fs9 = state.RegisterAlias("fs9", self.f25, 8, 0)
        self.add(self.fs9)
        # f26 is a callee-saved register
        self.f26 = state.Register("f26", 8)
        self.add(self.f26)
        self.fs10 = state.RegisterAlias("fs10", self.f26, 8, 0)
        self.add(self.fs10)
        # f27 is a callee-saved register
        self.f27 = state.Register("f27", 8)
        self.add(self.f27)
        self.fs11 = state.RegisterAlias("fs11", self.f27, 8, 0)
        self.add(self.fs11)
        # f28 is a temporary register
        self.f28 = state.Register("f28", 8)
        self.add(self.f28)
        self.ft8 = state.RegisterAlias("ft8", self.f28, 8, 0)
        self.add(self.ft8)
        # f29 is a temporary register
        self.f29 = state.Register("f29", 8)
        self.add(self.f29)
        self.ft9 = state.RegisterAlias("ft9", self.f29, 8, 0)
        self.add(self.ft9)
        # f30 is a temporary register
        self.f30 = state.Register("f30", 8)
        self.add(self.f30)
        self.ft10 = state.RegisterAlias("ft10", self.f30, 8, 0)
        self.add(self.ft10)
        # f31 is a temporary register
        self.f31 = state.Register("f31", 8)
        self.add(self.f31)
        self.ft11 = state.RegisterAlias("ft11", self.f31, 8, 0)
        self.add(self.ft11)

        # *** Vector Registers ***
        # NOTE: These exist, but are not supported

        # *** Control and Status Registers ***
        # NOTE: These exist, but aren't supported.
