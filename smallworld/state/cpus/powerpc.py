import typing

from ... import platforms
from .. import state
from . import cpu


class PowerPC(cpu.CPU):
    """CPU state for 32-bit PowerPC."""

    _GENERAL_PURPOSE_REGS = [f"r{i}" for i in range(0, 32)]

    def get_general_purpose_registers(self) -> typing.List[str]:
        return self._GENERAL_PURPOSE_REGS

    def __init__(self, wordsize):
        # *** General Purpose Registers ***
        # NOTE: Used expressive names for GPRs and FPRs.
        # gasm just refers to GPRs and FPRS by number.
        # They use the same numbers; it's very annoying.
        self.r0 = state.Register("r0", size=wordsize)
        # NOTE: GPR 1 is also the stack pointer.
        self.r1 = state.Register("r1", size=wordsize)
        self.sp = state.RegisterAlias("sp", self.r1, size=wordsize, offset=0)
        self.r2 = state.Register("r2", size=wordsize)
        self.r3 = state.Register("r3", size=wordsize)
        self.r4 = state.Register("r4", size=wordsize)
        self.r5 = state.Register("r5", size=wordsize)
        self.r6 = state.Register("r6", size=wordsize)
        self.r7 = state.Register("r7", size=wordsize)
        self.r8 = state.Register("r8", size=wordsize)
        self.r9 = state.Register("r9", size=wordsize)
        self.r10 = state.Register("r10", size=wordsize)
        self.r11 = state.Register("r11", size=wordsize)
        self.r12 = state.Register("r12", size=wordsize)
        self.r13 = state.Register("r13", size=wordsize)
        self.r14 = state.Register("r14", size=wordsize)
        self.r15 = state.Register("r15", size=wordsize)
        self.r16 = state.Register("r16", size=wordsize)
        self.r17 = state.Register("r17", size=wordsize)
        self.r18 = state.Register("r18", size=wordsize)
        self.r19 = state.Register("r19", size=wordsize)
        self.r20 = state.Register("r20", size=wordsize)
        self.r21 = state.Register("r21", size=wordsize)
        self.r22 = state.Register("r22", size=wordsize)
        self.r23 = state.Register("r23", size=wordsize)
        self.r24 = state.Register("r24", size=wordsize)
        self.r25 = state.Register("r25", size=wordsize)
        self.r26 = state.Register("r26", size=wordsize)
        self.r27 = state.Register("r27", size=wordsize)
        self.r28 = state.Register("r28", size=wordsize)
        self.r29 = state.Register("r29", size=wordsize)
        self.r30 = state.Register("r30", size=wordsize)
        # NOTE: GPR 31 is also the base pointer
        self.r31 = state.Register("r31", size=wordsize)
        self.bp = state.RegisterAlias("bp", self.r31, size=wordsize, offset=0)

        # Floating Point Registers
        # Always 8 bytes, regardless of wordsize.
        self.f0 = state.Register("f0", size=8)
        self.f1 = state.Register("f1", size=8)
        self.f2 = state.Register("f2", size=8)
        self.f3 = state.Register("f3", size=8)
        self.f4 = state.Register("f4", size=8)
        self.f5 = state.Register("f5", size=8)
        self.f6 = state.Register("f6", size=8)
        self.f7 = state.Register("f7", size=8)
        self.f8 = state.Register("f8", size=8)
        self.f9 = state.Register("f9", size=8)
        self.f10 = state.Register("f10", size=8)
        self.f11 = state.Register("f11", size=8)
        self.f12 = state.Register("f12", size=8)
        self.f13 = state.Register("f13", size=8)
        self.f14 = state.Register("f14", size=8)
        self.f15 = state.Register("f15", size=8)
        self.f16 = state.Register("f16", size=8)
        self.f17 = state.Register("f17", size=8)
        self.f18 = state.Register("f18", size=8)
        self.f19 = state.Register("f19", size=8)
        self.f20 = state.Register("f20", size=8)
        self.f21 = state.Register("f21", size=8)
        self.f22 = state.Register("f22", size=8)
        self.f23 = state.Register("f23", size=8)
        self.f24 = state.Register("f24", size=8)
        self.f25 = state.Register("f25", size=8)
        self.f26 = state.Register("f26", size=8)
        self.f27 = state.Register("f27", size=8)
        self.f28 = state.Register("f28", size=8)
        self.f29 = state.Register("f29", size=8)
        self.f30 = state.Register("f30", size=8)
        self.f31 = state.Register("f31", size=8)

        # *** Pointer Registers ***
        # Program Counter.
        # Not really a register; nothing can access it directly
        self.pc = state.Register("pc", size=wordsize)

        # Link Register
        self.lr = state.Register("lr", size=wordsize)

        # Counter Register
        # Acts either as a loop index, or a branch target register
        # Only `ctr` and `lr` can act as branch targets.
        self.ctr = state.Register("ctr", size=wordsize)

        # *** Condition Registers ***
        # Condition Register
        # The actual condition register `cr` is a single 32-bit register,
        # but it's broken into eight 4-bit fields which are accessed separately.
        self.cr0 = state.Register("cr0", size=1)  # Integer condition bits
        self.cr1 = state.Register("cr1", size=1)  # Floatibg point condition bits
        self.cr2 = state.Register("cr2", size=1)
        self.cr3 = state.Register("cr3", size=1)
        self.cr4 = state.Register("cr4", size=1)
        self.cr5 = state.Register("cr5", size=1)
        self.cr6 = state.Register("cr6", size=1)
        self.cr7 = state.Register("cr7", size=1)

        # Integer Exception Register
        self.xer = state.Register("xer", size=4)

        # Floating Point Status and Control Register
        self.fpsrc = state.Register("fpscr", size=4)

        # TODO: This only focuses on the user-facing registrers.
        # ppc has a huge number of privileged registers.
        # Extend this as needed.


class PowerPC32(PowerPC):
    """CPU state for 32-bit PowerPC."""

    mode = "ppc32"

    platform = platforms.Platform(
        platforms.Architecture.POWERPC32, platforms.Byteorder.BIG
    )

    def __init__(self):
        super().__init__(4)


class PowerPC64(PowerPC):
    """CPU state for 64-bit PowerPC."""

    mode = "ppc64"

    platform = platforms.Platform(
        platforms.Architecture.POWERPC64, platforms.Byteorder.BIG
    )

    def __init__(self):
        super().__init__(8)
