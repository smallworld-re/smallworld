import typing

from ... import platforms
from .. import state
from . import cpu

# ARM32 has a number of variants with very odd overlaps. Rather than risk
# copy-paste errors as I figure out who gets which control registers, I've
# implemented each subsystem variant in its own mixin.


class ARMCPUState(cpu.CPU):
    """Base class for ARM 32-bit CPU models

    All ARM CPUs share the same basic registers,
    but there are at least two dimensions of difference
    for the available modes.
    """

    # Special registers:
    # r13: stack pointer
    # r14: link register
    # r15: Program counter
    _GENERAL_PURPOSE_REGS = [f"r{i}" for i in range(0, 13)]

    def get_general_purpose_registers(self) -> typing.List[str]:
        return self._GENERAL_PURPOSE_REGS

    def __init__(self):
        # *** General-purpose registers ***
        self.r0 = state.Register("r0", size=4)
        self.r1 = state.Register("r1", size=4)
        self.r2 = state.Register("r2", size=4)
        self.r3 = state.Register("r3", size=4)
        self.r4 = state.Register("r4", size=4)
        self.r5 = state.Register("r5", size=4)
        self.r6 = state.Register("r6", size=4)
        self.r7 = state.Register("r7", size=4)
        self.r8 = state.Register("r8", size=4)
        # r9 doubles as the Static base pointer
        self.r9 = state.Register("r9", size=4)
        self.sb = state.RegisterAlias("sb", self.r9, size=4, offset=0)
        # r10 doubles as the Stack Limit pointer
        self.r10 = state.Register("r10", size=4)
        self.sl = state.RegisterAlias("sl", self.r10, size=4, offset=0)
        # r11 doubles as the Frame Pointer, if desired.
        self.r11 = state.Register("r11", size=4)
        self.fp = state.RegisterAlias("fp", self.r11, size=4, offset=0)
        # r12 doubles as the Intra-call scratch register
        self.r12 = state.Register("r12", size=4)
        self.ip = state.RegisterAlias("ip", self.r12, size=4, offset=0)
        self.sp = state.Register("sp", size=4)
        self.lr = state.Register("lr", size=4)
        self.pc = state.Register("pc", size=4)


class ARMCPUMixinM:
    """Abstract class for M-series CPUs.

    The main difference between M and R/A
    is the available system status registers.
    """

    def __init__(self):
        super().__init__()
        # *** Special Registers ***
        # Program Status Register
        # NOTE: PSR can be accessed through several masked aliases.
        # These are read-only, so I'm not including them.
        # - apsr: Just the condition flags
        # - ipsr: Just exception information
        # - epsr: Just execution state info
        # - iapsr: apsr | ipsr
        # - eapsr: apsr | epsr
        # - iepsr: ipsr | epsr
        # - xpsr: apsr | ipsr | epsr
        #
        # NOTE: Unicorn doesn't have a model for PSR, only its aliases
        self.psr = state.Register("psr", size=4)
        # Exception Mask Register
        self.primask = state.Register("primask", size=4)
        # Base Priority Mask Register
        self.basepri = state.Register("basepri", size=4)
        # Fault Mask Register
        self.faultmask = state.Register("faultmask", size=4)
        # Control register; includes a lot of flags.
        self.control = state.Register("control", size=4)

        # *** Stack Pointer Bank ***
        # sp is actually an alias to one of these two.
        # Exactly which one depends on a bit in control.
        # Emulators that care should be careful when loading state.

        # Main Stack Pointer
        self.msp = state.Register("msp", size=4)
        # Process Stack Pointer
        self.psp = state.Register("psp", size=4)


class ARMCPUMixinRA:
    """Mixin for R- or A-series CPUs.

    The main difference between M and R/A
    is the available system status registers.
    """

    def __init__(self):
        super().__init__()
        # *** Special Registers ***
        # Current Program Status Register
        # NOTE: CPSR can be accessed through several masked aliases.
        # These are read-only, so I'm not including them.
        # - isetstate: Just includes instruction set control bits
        # - itstate: Just includes state bits for Thumb IT instruction
        self.cpsr = state.Register("cpsr", size=4)
        # Saved Program Status Register
        self.spsr = state.Register("spsr", size=4)

        # *** Register Banks ***
        # sp, lr, and spsr are actually aliases to one of these.
        # Which one they reference depends on execution mode.
        # Emulators that care should be careful when loading state.
        # NOTE: Use User-mode copies of registers unless the mode has its own.

        # User-mode Stack Pointer
        self.sp_usr = state.Register("sp_usr", size=4)
        # User-mode Link Register
        self.lr_usr = state.Register("lr_usr", size=4)
        # User-mode r8
        self.r8_usr = state.Register("r8_usr", size=4)
        # User-mode r9
        self.r9_usr = state.Register("r9_usr", size=4)
        # User-mode r10
        self.r10_usr = state.Register("r10_usr", size=4)
        # User-mode r11
        self.r11_usr = state.Register("r11_usr", size=4)
        # User-mode r12
        self.r12_usr = state.Register("r12_usr", size=4)

        # Hypervisor Stack Pointer
        self.sp_hyp = state.Register("sp_hyp", size=4)
        # Hypervisor Saved PSR
        self.spsr_hyp = state.Register("spsr_hyp", size=4)
        # Hypervisor Exception Link Register
        # NOTE: This isn't so much banked, as it only exists in hypervisor mode.
        self.elr_hyp = state.Register("elr_hyp", size=4)

        # Supervisor Stack Pointer
        self.sp_svc = state.Register("sp_svc", size=4)
        # Supervisor Link Register
        self.lr_svc = state.Register("lr_svc", size=4)
        # Supervisor Saved PSR
        self.spsr_svc = state.Register("spsr_svc", size=4)

        # Abort-state Stack Pointer
        self.sp_abt = state.Register("sp_abt", size=4)
        # Abort-state Link Register
        self.lr_abt = state.Register("lr_abt", size=4)
        # Abort-state Saved PSR
        self.spsr_abt = state.Register("spsr_abt", size=4)

        # Undefined-mode Stack Pointer
        self.sp_und = state.Register("sp_und", size=4)
        # Undefined-mode Link Register
        self.lr_und = state.Register("lr_und", size=4)
        # Undefined-mode Saved PSR
        self.spsr_und = state.Register("spsr_und", size=4)

        # Monitor-mode Stack Pointer
        self.sp_mon = state.Register("sp_mon", size=4)
        # Monitor-mode Link Register
        self.lr_mon = state.Register("lr_mon", size=4)
        # Monitor-mode Saved PSR
        self.spsr_mon = state.Register("spsr_mon", size=4)

        # IRQ-mode Stack Pointer
        self.sp_irq = state.Register("sp_irq", size=4)
        # IRQ-mode Link Register
        self.lr_irq = state.Register("lr_irq", size=4)
        # IRQ-mode Saved PSR
        self.spsr_irq = state.Register("spsr_irq", size=4)

        # FIQ-mode Stack Pointer
        self.sp_fiq = state.Register("sp_fiq", size=4)
        # FIQ-mode Link Register
        self.lr_fiq = state.Register("lr_fiq", size=4)
        # FIQ-mode Saved PSR
        self.spsr_fiq = state.Register("spsr_fiq", size=4)
        # FIQ-mode r8
        self.r8_fiq = state.Register("r8_fiq", size=4)
        # FIQ-mode r9
        self.r9_fiq = state.Register("r9_fiq", size=4)
        # FIQ-mode r10
        self.r10_fiq = state.Register("r10_fiq", size=4)
        # FIQ-mode r11
        self.r11_fiq = state.Register("r11_fiq", size=4)
        # FIQ-mode r12
        self.r12_fiq = state.Register("r12_fiq", size=4)


class ARMCPUMixinFPEL:
    """Mixin for little-endian ARM CPUs with FP extensions

    This is one kind of floating-point extension
    which offers 64-bit scalar operations
    """

    def __init__(self):
        super().__init__()
        # *** Floating point control registers ***
        # Floating-point Status and Control Register
        self.fpscr = state.Register("fpscr", size=4)
        # Floating-point Exception Control Register
        self.fpexc = state.Register("fpexc", size=4)
        # Floating-point System ID Register
        self.fpsid = state.Register("fpsid", size=4)
        # Media and VFP Feature Register 0
        self.mvfr0 = state.Register("mvfr0", size=4)
        # Media and VFP Feature Register 1
        self.mvfr1 = state.Register("mvfr1", size=4)

        # *** Floating point registers ***
        self.d0 = state.Register("d0", size=8)
        self.s0 = state.RegisterAlias("s0", self.d0, size=4, offset=0)
        self.s1 = state.RegisterAlias("s1", self.d0, size=4, offset=4)
        self.d1 = state.Register("d1", size=8)
        self.s2 = state.RegisterAlias("s2", self.d1, size=4, offset=0)
        self.s3 = state.RegisterAlias("s3", self.d1, size=4, offset=4)
        self.d2 = state.Register("d2", size=8)
        self.s4 = state.RegisterAlias("s4", self.d2, size=4, offset=0)
        self.s5 = state.RegisterAlias("s5", self.d2, size=4, offset=4)
        self.d3 = state.Register("d3", size=8)
        self.s6 = state.RegisterAlias("s6", self.d3, size=4, offset=0)
        self.s7 = state.RegisterAlias("s7", self.d3, size=4, offset=4)
        self.d4 = state.Register("d4", size=8)
        self.s8 = state.RegisterAlias("s8", self.d4, size=4, offset=0)
        self.s9 = state.RegisterAlias("s9", self.d4, size=4, offset=4)
        self.d5 = state.Register("d5", size=8)
        self.s10 = state.RegisterAlias("s10", self.d5, size=4, offset=0)
        self.s11 = state.RegisterAlias("s11", self.d5, size=4, offset=4)
        self.d6 = state.Register("d6", size=8)
        self.s12 = state.RegisterAlias("s12", self.d6, size=4, offset=0)
        self.s13 = state.RegisterAlias("s13", self.d6, size=4, offset=4)
        self.d7 = state.Register("d7", size=8)
        self.s14 = state.RegisterAlias("s14", self.d7, size=4, offset=0)
        self.s15 = state.RegisterAlias("s15", self.d7, size=4, offset=4)
        self.d8 = state.Register("d8", size=8)
        self.s16 = state.RegisterAlias("s16", self.d8, size=4, offset=0)
        self.s17 = state.RegisterAlias("s17", self.d8, size=4, offset=4)
        self.d9 = state.Register("d9", size=8)
        self.s18 = state.RegisterAlias("s18", self.d9, size=4, offset=0)
        self.s19 = state.RegisterAlias("s19", self.d9, size=4, offset=4)
        self.d10 = state.Register("d10", size=8)
        self.s20 = state.RegisterAlias("s20", self.d10, size=4, offset=0)
        self.s21 = state.RegisterAlias("s21", self.d10, size=4, offset=4)
        self.d11 = state.Register("d11", size=8)
        self.s22 = state.RegisterAlias("s22", self.d11, size=4, offset=0)
        self.s23 = state.RegisterAlias("s23", self.d11, size=4, offset=4)
        self.d12 = state.Register("d12", size=8)
        self.s24 = state.RegisterAlias("s24", self.d12, size=4, offset=0)
        self.s25 = state.RegisterAlias("s25", self.d12, size=4, offset=4)
        self.d13 = state.Register("d13", size=8)
        self.s26 = state.RegisterAlias("s26", self.d13, size=4, offset=0)
        self.s27 = state.RegisterAlias("s27", self.d13, size=4, offset=4)
        self.d14 = state.Register("d14", size=8)
        self.s28 = state.RegisterAlias("s28", self.d14, size=4, offset=0)
        self.s29 = state.RegisterAlias("s29", self.d14, size=4, offset=4)
        self.d15 = state.Register("d15", size=8)
        self.s30 = state.RegisterAlias("s30", self.d15, size=4, offset=0)
        self.s31 = state.RegisterAlias("s31", self.d15, size=4, offset=4)


class ARMCPUMixinVFPEL:
    """Mixin for little-endian ARM CPUs with VFP/NEON mixins

    This is one kind of floating-point extension
    which supports up to 128-bit scalar and SIMD vector operations.

    VFP and NEON are always optional extensions;
    The two can exist independently, and VFP can support either
    16 or 32 double registers.
    This is the maximal set of registers, assuming both are supported.
    """

    def __init__(self):
        super().__init__()
        # *** Floating-point Control Registers ***
        # Floating-point Status and Control Register
        self.fpscr = state.Register("fpscr", size=4)
        # Floating-point Exception Control Register
        self.fpexc = state.Register("fpexc", size=4)
        # Floating-point System ID Register
        self.fpsid = state.Register("fpsid", size=4)
        # Media and VFP Feature Register 0
        self.mvfr0 = state.Register("mvfr0", size=4)
        # Media and VFP Feature Register 1
        self.mvfr1 = state.Register("mvfr1", size=4)
        # *** Floating-point Registers ****
        self.q0 = state.Register("q0", size=16)
        self.d0 = state.RegisterAlias("d0", self.q0, size=8, offset=0)
        self.s0 = state.RegisterAlias("s0", self.q0, size=4, offset=0)
        self.s1 = state.RegisterAlias("s1", self.q0, size=4, offset=4)
        self.d1 = state.RegisterAlias("d1", self.q0, size=8, offset=8)
        self.s2 = state.RegisterAlias("s2", self.q0, size=4, offset=8)
        self.s3 = state.RegisterAlias("s3", self.q0, size=4, offset=12)
        self.q1 = state.Register("q1", size=16)
        self.d2 = state.RegisterAlias("d2", self.q1, size=8, offset=0)
        self.s4 = state.RegisterAlias("s4", self.q1, size=4, offset=0)
        self.s5 = state.RegisterAlias("s5", self.q1, size=4, offset=4)
        self.d3 = state.RegisterAlias("d3", self.q1, size=8, offset=8)
        self.s6 = state.RegisterAlias("s6", self.q1, size=4, offset=8)
        self.s7 = state.RegisterAlias("s7", self.q1, size=4, offset=12)
        self.q2 = state.Register("q2", size=16)
        self.d4 = state.RegisterAlias("d4", self.q2, size=8, offset=0)
        self.s8 = state.RegisterAlias("s8", self.q2, size=4, offset=0)
        self.s9 = state.RegisterAlias("s9", self.q2, size=4, offset=4)
        self.d5 = state.RegisterAlias("d5", self.q2, size=8, offset=8)
        self.s10 = state.RegisterAlias("s10", self.q2, size=4, offset=8)
        self.s11 = state.RegisterAlias("s11", self.q2, size=4, offset=12)
        self.q3 = state.Register("q3", size=16)
        self.d6 = state.RegisterAlias("d6", self.q3, size=8, offset=0)
        self.s12 = state.RegisterAlias("s12", self.q3, size=4, offset=0)
        self.s13 = state.RegisterAlias("s13", self.q3, size=4, offset=4)
        self.d7 = state.RegisterAlias("d7", self.q3, size=8, offset=8)
        self.s14 = state.RegisterAlias("s14", self.q3, size=4, offset=8)
        self.s15 = state.RegisterAlias("s15", self.q3, size=4, offset=12)
        self.q4 = state.Register("q4", size=16)
        self.d8 = state.RegisterAlias("d8", self.q4, size=8, offset=0)
        self.s16 = state.RegisterAlias("s16", self.q4, size=4, offset=0)
        self.s17 = state.RegisterAlias("s17", self.q4, size=4, offset=4)
        self.d9 = state.RegisterAlias("d9", self.q4, size=8, offset=8)
        self.s18 = state.RegisterAlias("s18", self.q4, size=4, offset=8)
        self.s19 = state.RegisterAlias("s19", self.q4, size=4, offset=12)
        self.q5 = state.Register("q5", size=16)
        self.d10 = state.RegisterAlias("d10", self.q5, size=8, offset=0)
        self.s20 = state.RegisterAlias("s20", self.q5, size=4, offset=0)
        self.s21 = state.RegisterAlias("s21", self.q5, size=4, offset=4)
        self.d11 = state.RegisterAlias("d11", self.q5, size=8, offset=8)
        self.s22 = state.RegisterAlias("s22", self.q5, size=4, offset=8)
        self.s23 = state.RegisterAlias("s23", self.q5, size=4, offset=12)
        self.q6 = state.Register("q6", size=16)
        self.d12 = state.RegisterAlias("d12", self.q6, size=8, offset=0)
        self.s24 = state.RegisterAlias("s24", self.q6, size=4, offset=0)
        self.s25 = state.RegisterAlias("s25", self.q6, size=4, offset=4)
        self.d13 = state.RegisterAlias("d13", self.q6, size=8, offset=8)
        self.s26 = state.RegisterAlias("s26", self.q6, size=4, offset=8)
        self.s27 = state.RegisterAlias("s27", self.q6, size=4, offset=12)
        self.q7 = state.Register("q7", size=16)
        self.d14 = state.RegisterAlias("d14", self.q7, size=8, offset=0)
        self.s28 = state.RegisterAlias("s28", self.q7, size=4, offset=0)
        self.s29 = state.RegisterAlias("s29", self.q7, size=4, offset=4)
        self.d15 = state.RegisterAlias("d15", self.q7, size=8, offset=8)
        self.s30 = state.RegisterAlias("s30", self.q7, size=4, offset=8)
        self.s31 = state.RegisterAlias("s31", self.q7, size=4, offset=12)
        # NOTE: This isn't a typo; there are only 32 single-precision sX registers
        # This does mean that only half the VFP register space can be used
        # for single-precision arithmetic.
        self.q8 = state.Register("q8", size=16)
        self.d16 = state.RegisterAlias("d16", self.q8, size=8, offset=0)
        self.d17 = state.RegisterAlias("d17", self.q8, size=8, offset=8)
        self.q9 = state.Register("q9", size=16)
        self.d18 = state.RegisterAlias("d18", self.q9, size=8, offset=0)
        self.d19 = state.RegisterAlias("d19", self.q9, size=8, offset=8)
        self.q10 = state.Register("q10", size=16)
        self.d20 = state.RegisterAlias("d20", self.q10, size=8, offset=0)
        self.d21 = state.RegisterAlias("d21", self.q10, size=8, offset=8)
        self.q11 = state.Register("q11", size=16)
        self.d22 = state.RegisterAlias("d22", self.q11, size=8, offset=0)
        self.d23 = state.RegisterAlias("d23", self.q11, size=8, offset=8)
        self.q12 = state.Register("q12", size=16)
        self.d24 = state.RegisterAlias("d24", self.q12, size=8, offset=0)
        self.d25 = state.RegisterAlias("d25", self.q12, size=8, offset=8)
        self.q13 = state.Register("q13", size=16)
        self.d26 = state.RegisterAlias("d26", self.q13, size=8, offset=0)
        self.d27 = state.RegisterAlias("d27", self.q13, size=8, offset=8)
        self.q14 = state.Register("q14", size=16)
        self.d28 = state.RegisterAlias("d28", self.q14, size=8, offset=0)
        self.d29 = state.RegisterAlias("d29", self.q14, size=8, offset=8)
        self.q15 = state.Register("q15", size=16)
        self.d30 = state.RegisterAlias("d30", self.q15, size=8, offset=0)
        self.d31 = state.RegisterAlias("d31", self.q15, size=8, offset=8)


class ARMv5TCPUState(ARMCPUMixinM, ARMCPUState):
    """CPU Model for ARMv5t little-endian"""

    @classmethod
    def get_platform(cls) -> platforms.Platform:
        return platforms.Platform(
            platforms.Architecture.ARM_V5T, platforms.Byteorder.LITTLE
        )


class ARMv6MCPUState(ARMCPUMixinFPEL, ARMCPUMixinM, ARMCPUState):
    """CPU Model for ARMv6-M little-endian"""

    @classmethod
    def get_platform(cls) -> platforms.Platform:
        return platforms.Platform(
            platforms.Architecture.ARM_V6M, platforms.Byteorder.LITTLE
        )


class ARMv6MThumbCPUState(ARMv6MCPUState):
    @classmethod
    def get_platform(cls) -> platforms.Platform:
        return platforms.Platform(
            platforms.Architecture.ARM_V6M_THUMB, platforms.Byteorder.LITTLE
        )


class ARMv7MCPUState(ARMCPUMixinFPEL, ARMCPUMixinM, ARMCPUState):
    """CPU Model for ARMv7-M little-endian"""

    @classmethod
    def get_platform(cls) -> platforms.Platform:
        return platforms.Platform(
            platforms.Architecture.ARM_V7M, platforms.Byteorder.LITTLE
        )


class ARMv7RCPUState(ARMCPUMixinVFPEL, ARMCPUMixinRA, ARMCPUState):
    """CPU Model for ARMv7-R little-endian"""

    # TODO: v7r and v7a have different MMUs, which I don't implement yet.
    @classmethod
    def get_platform(cls) -> platforms.Platform:
        return platforms.Platform(
            platforms.Architecture.ARM_V7R, platforms.Byteorder.LITTLE
        )


class ARMv7ACPUState(ARMCPUMixinVFPEL, ARMCPUMixinRA, ARMCPUState):
    """CPU Model for ARMv7-A little-endian"""

    @classmethod
    def get_platform(cls) -> platforms.Platform:
        return platforms.Platform(
            platforms.Architecture.ARM_V7A, platforms.Byteorder.LITTLE
        )
