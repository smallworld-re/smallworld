from ... import platforms
from .. import state
from .cpu import CPU


class M68K(CPU):
    """Motorola 68K CPU state model"""

    platform = platforms.Platform(platforms.Architecture.M68K, platforms.Byteorder.BIG)

    def __init__(self):
        super().__init__()
        # Data registers
        self.d0 = state.Register("d0", 4)
        self.add(self.d0)
        self.d1 = state.Register("d1", 4)
        self.add(self.d1)
        self.d2 = state.Register("d2", 4)
        self.add(self.d2)
        self.d3 = state.Register("d3", 4)
        self.add(self.d3)
        self.d4 = state.Register("d4", 4)
        self.add(self.d4)
        self.d5 = state.Register("d5", 4)
        self.add(self.d5)
        self.d6 = state.Register("d6", 4)
        self.add(self.d6)
        self.d7 = state.Register("d7", 4)
        self.add(self.d7)
        # Address registers
        self.a0 = state.Register("a0", 4)
        self.add(self.a0)
        self.a1 = state.Register("a1", 4)
        self.add(self.a1)
        self.a2 = state.Register("a2", 4)
        self.add(self.a2)
        self.a3 = state.Register("a3", 4)
        self.add(self.a3)
        self.a4 = state.Register("a4", 4)
        self.add(self.a4)
        self.a5 = state.Register("a5", 4)
        self.add(self.a5)
        # a6 is the frame pointer in some calling conventions.
        self.a6 = state.Register("a6", 4)
        self.add(self.a6)
        self.fp = state.RegisterAlias("fp", self.a6, 4, 0)
        self.add(self.fp)
        # a7 is the stack pointer.
        # It is aliased to "sp" in many disassemblers
        #
        # a7 is actually an alias for one of three registers
        # depending on system mode:
        #
        # - usp; the User Stack Pointer
        # - isp; the Interrupt Stack Pointer (called Supervisor Stack Pointer on M68010 and earlier)
        # - msp; the Master Stack Pointer (M68020 and later)
        #
        # SmallWorld's machine state assumes that a7 is aliased to usp.
        self.usp = state.Register("usp", 4)
        self.add(self.usp)
        self.a7 = state.RegisterAlias("a7", self.usp, 4, 0)
        self.add(self.a7)
        self.sp = state.RegisterAlias("sp", self.usp, 4, 0)
        self.add(self.sp)
        # Program Counter
        self.pc = state.Register("pc", 4)
        self.add(self.pc)
        # Floating-point control register
        self.fpcr = state.Register("fpcr", 4)
        self.add(self.fpcr)
        # Floating-point status register
        self.fpsr = state.Register("fpsr", 4)
        self.add(self.fpsr)
        # Floating-point instruction address register
        self.fpiar = state.Register("fpiar", 4)
        self.add(self.fpiar)
        # Floating-point registers.
        # NOTE: These use the same 80-bit format as x87
        self.fp0 = state.Register("fp0", 10)
        self.add(self.fp0)
        self.fp1 = state.Register("fp1", 10)
        self.add(self.fp1)
        self.fp2 = state.Register("fp2", 10)
        self.add(self.fp2)
        self.fp3 = state.Register("fp3", 10)
        self.add(self.fp3)
        self.fp4 = state.Register("fp4", 10)
        self.add(self.fp4)
        self.fp5 = state.Register("fp5", 10)
        self.add(self.fp5)
        self.fp6 = state.Register("fp6", 10)
        self.add(self.fp6)
        self.fp7 = state.Register("fp7", 10)
        self.add(self.fp7)
        # NOTE: Everything past this point is privileged state
        # Interrupt stack pointer
        # Also called the Supervisor stack pointer in earlier versions
        self.isp = state.Register("isp", 4)
        self.add(self.isp)
        self.ssp = state.RegisterAlias("ssp", self.isp, 4, 0)
        self.add(self.ssp)
        # Master stack pointer
        self.msp = state.Register("msp", 4)
        self.add(self.msp)
        # Status register
        # Include condition code register as a one-byte alias
        self.sr = state.Register("sr", 2)
        self.add(self.sr)
        self.ccr = state.RegisterAlias("ccr", self.sr, 1, 0)
        self.add(self.ccr)
        # Interrupt vector base register
        self.vbr = state.Register("vbr", 4)
        self.add(self.vbr)
        # Function code registers
        self.sfc = state.Register("sfc", 1)
        self.add(self.sfc)
        self.dfc = state.Register("dfc", 1)
        self.add(self.dfc)
        # Cache control register
        self.cacr = state.Register("cacr", 4)
        self.add(self.cacr)
        # User root pointer register
        self.urp = state.Register("urp", 4)
        self.add(self.urp)
        # Supervisor root pointer register
        self.srp = state.Register("srp", 4)
        self.add(self.srp)
        # Translation control register
        self.tc = state.Register("tc", 2)
        self.add(self.tc)
        # Data transparent translation registers
        self.dtt0 = state.Register("dtt0", 4)
        self.add(self.dtt0)
        self.dtt1 = state.Register("dtt1", 4)
        self.add(self.dtt1)
        # Instruction transparent translationr registers
        self.itt0 = state.Register("itt0", 4)
        self.add(self.itt0)
        self.itt1 = state.Register("itt1", 4)
        self.add(self.itt1)
        # MMU status register
        self.mmusr = state.Register("mmusr", 4)
        self.add(self.mmusr)
