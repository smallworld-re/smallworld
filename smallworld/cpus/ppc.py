from ..state import CPU, Register, RegisterAlias


class PowerPCCPUState(CPU):
    """CPU state for 32-bit PowerPC."""

    arch = "powerpc"
    byteorder = "big"

    GENERAL_PURPOSE_REGS = [f"r{i}" for i in range(0, 32)]

    def __init__(self, wordsize):
        # *** General Purpose Registers ***
        # NOTE: Used expressive names for GPRs and FPRs.
        # gasm just refers to GPRs and FPRS by number.
        # They use the same numbers; it's very annoying.
        self.r0 = Register("r0", width=wordsize)
        # NOTE: GPR 1 is also the stack pointer.
        self.r1 = Register("r1", width=wordsize)
        self.sp = RegisterAlias("sp", self.r1, width=wordsize, offset=0)
        self.r2 = Register("r2", width=wordsize)
        self.r3 = Register("r3", width=wordsize)
        self.r4 = Register("r4", width=wordsize)
        self.r5 = Register("r5", width=wordsize)
        self.r6 = Register("r6", width=wordsize)
        self.r7 = Register("r7", width=wordsize)
        self.r8 = Register("r8", width=wordsize)
        self.r9 = Register("r9", width=wordsize)
        self.r10 = Register("r10", width=wordsize)
        self.r11 = Register("r11", width=wordsize)
        self.r12 = Register("r12", width=wordsize)
        self.r13 = Register("r13", width=wordsize)
        self.r14 = Register("r14", width=wordsize)
        self.r15 = Register("r15", width=wordsize)
        self.r16 = Register("r16", width=wordsize)
        self.r17 = Register("r17", width=wordsize)
        self.r18 = Register("r18", width=wordsize)
        self.r19 = Register("r19", width=wordsize)
        self.r20 = Register("r20", width=wordsize)
        self.r21 = Register("r21", width=wordsize)
        self.r22 = Register("r22", width=wordsize)
        self.r23 = Register("r23", width=wordsize)
        self.r24 = Register("r24", width=wordsize)
        self.r25 = Register("r25", width=wordsize)
        self.r26 = Register("r26", width=wordsize)
        self.r27 = Register("r27", width=wordsize)
        self.r28 = Register("r28", width=wordsize)
        self.r29 = Register("r29", width=wordsize)
        self.r30 = Register("r30", width=wordsize)
        # NOTE: GPR 31 is also the base pointer
        self.r31 = Register("r31", width=wordsize)
        self.bp = RegisterAlias("bp", self.r31, width=wordsize, offset=0)

        # Floating Point Registers
        # Always 8 bytes, regardless of wordsize.
        self.f0 = Register("f0", width=8)
        self.f1 = Register("f1", width=8)
        self.f2 = Register("f2", width=8)
        self.f3 = Register("f3", width=8)
        self.f4 = Register("f4", width=8)
        self.f5 = Register("f5", width=8)
        self.f6 = Register("f6", width=8)
        self.f7 = Register("f7", width=8)
        self.f8 = Register("f8", width=8)
        self.f9 = Register("f9", width=8)
        self.f10 = Register("f10", width=8)
        self.f11 = Register("f11", width=8)
        self.f12 = Register("f12", width=8)
        self.f13 = Register("f13", width=8)
        self.f14 = Register("f14", width=8)
        self.f15 = Register("f15", width=8)
        self.f16 = Register("f16", width=8)
        self.f17 = Register("f17", width=8)
        self.f18 = Register("f18", width=8)
        self.f19 = Register("f19", width=8)
        self.f20 = Register("f20", width=8)
        self.f21 = Register("f21", width=8)
        self.f22 = Register("f22", width=8)
        self.f23 = Register("f23", width=8)
        self.f24 = Register("f24", width=8)
        self.f25 = Register("f25", width=8)
        self.f26 = Register("f26", width=8)
        self.f27 = Register("f27", width=8)
        self.f28 = Register("f28", width=8)
        self.f29 = Register("f29", width=8)
        self.f30 = Register("f30", width=8)
        self.f31 = Register("f31", width=8)

        # *** Pointer Registers ***
        # Program Counter.
        # Not really a register; nothing can access it directly
        self.pc = Register("pc", width=wordsize)

        # Link Register
        self.lr = Register("lr", width=wordsize)

        # Counter Register
        # Acts either as a loop index, or a branch target register
        # Only `ctr` and `lr` can act as branch targets.
        self.ctr = Register("ctr", width=wordsize)

        # *** Condition Registers ***
        # Condition Register
        # The actual condition register `cr` is a single 32-bit register,
        # but it's broken into eight 4-bit fields which are accessed separately.
        self.cr0 = Register("cr0", width=1)  # Integer condition bits
        self.cr1 = Register("cr1", width=1)  # Floatibg point condition bits
        self.cr2 = Register("cr2", width=1)
        self.cr3 = Register("cr3", width=1)
        self.cr4 = Register("cr4", width=1)
        self.cr5 = Register("cr5", width=1)
        self.cr6 = Register("cr6", width=1)
        self.cr7 = Register("cr7", width=1)

        # Integer Exception Register
        self.xer = Register("xer", width=4)

        # Floating Point Status and Control Register
        self.fpsrc = Register("fpscr", width=4)

        # TODO: This only focuses on the user-facing registrers.
        # ppc has a huge number of privileged registers.
        # Extend this as needed.


class PowerPC32CPUState(PowerPCCPUState):
    """CPU state for 32-bit PowerPC"""

    mode = "ppc32"

    def __init__(self):
        super().__init__(8)


class PowerPC64CPUState(PowerPCCPUState):
    """CPU state for 64-bit PowerPC"""

    mode = "ppc64"

    def __init__(self):
        super().__init__(8)
