from ... import platforms
from .. import state
from . import cpu


class MSP430CPU(cpu.CPU):
    def __init__(self):
        super().__init__()
        # r0 is also the program counter.
        # I'm not sure it's actually possible to reference r0 directly...
        self.pc = state.Register("pc", self.reg_size)
        self.add(self.pc)
        self.r0 = state.RegisterAlias("r0", self.pc, self.reg_size, 0)
        self.add(self.r0)
        # r1 is the system stack pointer
        self.sp = state.Register("sp", self.reg_size)
        self.add(self.sp)
        self.r1 = state.RegisterAlias("r1", self.sp, self.reg_size, 0)
        self.add(self.r1)
        # r2 is actually two different registers depending on the addressing mode.
        # For the purposes of this model, r2 will always alias sr.
        self.sr = state.Register("sr", self.reg_size)
        self.add(self.sr)
        self.r2 = state.RegisterAlias("r2", self.sr, self.reg_size, 0)
        self.add(self.r2)
        # msp430 has an interesting feature where
        # the values of r2 and r3 assume various values depending
        # on the addressing mode of the instruction in which they're used.
        #
        # Since setting these is a non-starter,
        # they are wired to zero in this model
        self.cg1 = state.FixedRegister("cg1", self.reg_size, 0)
        self.add(self.cg1)
        # r3 is constant generator 2
        self.cg2 = state.FixedRegister("cg2", self.reg_size, 0)
        self.add(self.cg2)
        self.r3 = state.RegisterAlias("r3", self.cg2, self.reg_size, 0)
        self.add(self.r3)
        # General-purpose registers
        self.r4 = state.Register("r4", self.reg_size)
        self.add(self.r4)
        self.r5 = state.Register("r5", self.reg_size)
        self.add(self.r5)
        self.r6 = state.Register("r6", self.reg_size)
        self.add(self.r6)
        self.r7 = state.Register("r7", self.reg_size)
        self.add(self.r7)
        self.r8 = state.Register("r8", self.reg_size)
        self.add(self.r8)
        self.r9 = state.Register("r9", self.reg_size)
        self.add(self.r9)
        self.r10 = state.Register("r10", self.reg_size)
        self.add(self.r10)
        self.r11 = state.Register("r11", self.reg_size)
        self.add(self.r11)
        self.r12 = state.Register("r12", self.reg_size)
        self.add(self.r12)
        self.r13 = state.Register("r13", self.reg_size)
        self.add(self.r13)
        self.r14 = state.Register("r14", self.reg_size)
        self.add(self.r14)
        self.r15 = state.Register("r15", self.reg_size)
        self.add(self.r15)


class MSP430(MSP430CPU):
    platform = platforms.Platform(
        platforms.Architecture.MSP430, platforms.Byteorder.LITTLE
    )
    reg_size = 2


class MSP430X(MSP430CPU):
    platform = platforms.Platform(
        platforms.Architecture.MSP430X, platforms.Byteorder.LITTLE
    )
    # msp430x's registers are 20 bits,
    # but ghidra and angr model them as 32 bits.
    # They get angry if you try to use fewer.
    reg_size = 4
