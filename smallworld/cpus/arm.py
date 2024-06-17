from ..state import CPU, Register, RegisterAlias

# ARM32 has a number of variants with very odd overlaps.
# Rather than risk copy-paste errors as I figure out who gets which control registers,
# I've implemented each subsystem variant in its own mixin.


class ARMCPUState(CPU):
    """Base class for ARM 32-bit CPU models

    All ARM CPUs share the same basic registers,
    but there are at least two dimensions of difference
    for the available modes.
    """

    arch = "arm"
    # Special registers:
    # r13: stack pointer
    # r14: link register
    # r15: Program counter
    GENERAL_PURPOSE_REGS = [f"r{i}" for i in range(0, 13)]

    def __init__(self):
        # *** General-purpose registers ***
        self.r0 = Register("r0", width=4)
        self.r1 = Register("r1", width=4)
        self.r2 = Register("r2", width=4)
        self.r3 = Register("r3", width=4)
        self.r4 = Register("r4", width=4)
        self.r5 = Register("r5", width=4)
        self.r6 = Register("r6", width=4)
        self.r7 = Register("r7", width=4)
        self.r8 = Register("r8", width=4)
        # r9 doubles as the Static base pointer
        self.r9 = Register("r9", width=4)
        self.sb = RegisterAlias("sb", self.r9, width=4, offset=0)
        # r10 doubles as the Stack Limit pointer
        self.r10 = Register("r10", width=4)
        self.sl = RegisterAlias("sl", self.r10, width=4, offset=0)
        # r11 doubles as the Frame Pointer, if desired.
        self.r11 = Register("r11", width=4)
        self.fp = RegisterAlias("fp", self.r11, width=4, offset=0)
        # r12 doubles as the Intra-call scratch register
        self.r12 = Register("r12", width=4)
        self.ip = RegisterAlias("ip", self.r12, width=4, offset=0)
        self.sp = Register("sp", width=4)
        self.lr = Register("lr", width=4)
        self.pc = Register("pc", width=4)


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
        self.psr = Register("psr", width=4)
        # Exception Mask Register
        self.primask = Register("primask", width=4)
        # Base Priority Mask Register
        self.basepri = Register("basepri", width=4)
        # Fault Mask Register
        self.faultmask = Register("faultmask", width=4)
        # Control register; includes a lot of flags.
        self.control = Register("control", width=4)

        # *** Stack Pointer Bank ***
        # sp is actually an alias to one of these two.
        # Exactly which one depends on a bit in control.
        # Emulators that care should be careful when loading state.

        # Main Stack Pointer
        self.msp = Register("msp", width=4)
        # Process Stack Pointer
        self.psp = Register("psp", width=4)


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
        self.cpsr = Register("cpsr", width=4)
        # Saved Program Status Register
        self.spsr = Register("spsr", width=4)

        # *** Register Banks ***
        # sp, lr, and spsr are actually aliases to one of these.
        # Which one they reference depends on execution mode.
        # Emulators that care should be careful when loading state.
        # NOTE: Use User-mode copies of registers unless the mode has its own.

        # User-mode Stack Pointer
        self.sp_usr = Register("sp_usr", width=4)
        # User-mode Link Register
        self.lr_usr = Register("lr_usr", width=4)
        # User-mode r8
        self.r8_usr = Register("r8_usr", width=4)
        # User-mode r9
        self.r9_usr = Register("r9_usr", width=4)
        # User-mode r10
        self.r10_usr = Register("r10_usr", width=4)
        # User-mode r11
        self.r11_usr = Register("r11_usr", width=4)
        # User-mode r12
        self.r12_usr = Register("r12_usr", width=4)

        # Hypervisor Stack Pointer
        self.sp_hyp = Register("sp_hyp", width=4)
        # Hypervisor Saved PSR
        self.spsr_hyp = Register("spsr_hyp", width=4)
        # Hypervisor Exception Link Register
        # NOTE: This isn't so much banked, as it only exists in hypervisor mode.
        self.elr_hyp = Register("elr_hyp", width=4)

        # Supervisor Stack Pointer
        self.sp_svc = Register("sp_svc", width=4)
        # Supervisor Link Register
        self.lr_svc = Register("lr_svc", width=4)
        # Supervisor Saved PSR
        self.spsr_svc = Register("spsr_svc", width=4)

        # Abort-state Stack Pointer
        self.sp_abt = Register("sp_abt", width=4)
        # Abort-state Link Register
        self.lr_abt = Register("lr_abt", width=4)
        # Abort-state Saved PSR
        self.spsr_abt = Register("spsr_abt", width=4)

        # Undefined-mode Stack Pointer
        self.sp_und = Register("sp_und", width=4)
        # Undefined-mode Link Register
        self.lr_und = Register("lr_und", width=4)
        # Undefined-mode Saved PSR
        self.spsr_und = Register("spsr_und", width=4)

        # Monitor-mode Stack Pointer
        self.sp_mon = Register("sp_mon", width=4)
        # Monitor-mode Link Register
        self.lr_mon = Register("lr_mon", width=4)
        # Monitor-mode Saved PSR
        self.spsr_mon = Register("spsr_mon", width=4)

        # IRQ-mode Stack Pointer
        self.sp_irq = Register("sp_irq", width=4)
        # IRQ-mode Link Register
        self.lr_irq = Register("lr_irq", width=4)
        # IRQ-mode Saved PSR
        self.spsr_irq = Register("spsr_irq", width=4)

        # FIQ-mode Stack Pointer
        self.sp_fiq = Register("sp_fiq", width=4)
        # FIQ-mode Link Register
        self.lr_fiq = Register("lr_fiq", width=4)
        # FIQ-mode Saved PSR
        self.spsr_fiq = Register("spsr_fiq", width=4)
        # FIQ-mode r8
        self.r8_fiq = Register("r8_fiq", width=4)
        # FIQ-mode r9
        self.r9_fiq = Register("r9_fiq", width=4)
        # FIQ-mode r10
        self.r10_fiq = Register("r10_fiq", width=4)
        # FIQ-mode r11
        self.r11_fiq = Register("r11_fiq", width=4)
        # FIQ-mode r12
        self.r12_fiq = Register("r12_fiq", width=4)


class ARMCPUMixinFPEL:
    """Mixin for little-endian ARM CPUs with FP extensions

    This is one kind of floating-point extension
    which offers 64-bit scalar operations
    """

    byteorder = "little"

    def __init__(self):
        super().__init__()
        # *** Floating point control registers ***
        # Floating-point Status and Control Register
        self.fpscr = Register("fpscr", width=4)
        # Floating-point Exception Control Register
        self.fpexc = Register("fpexc", width=4)
        # Floating-point System ID Register
        self.fpsid = Register("fpsid", width=4)
        # Media and VFP Feature Register 0
        self.mvfr0 = Register("mvfr0", width=4)
        # Media and VFP Feature Register 1
        self.mvfr1 = Register("mvfr1", width=4)

        # *** Floating point registers ***
        self.d0 = Register("d0", width=8)
        self.s0 = RegisterAlias("s0", self.d0, width=4, offset=0)
        self.s1 = RegisterAlias("s1", self.d0, width=4, offset=4)
        self.d1 = Register("d1", width=8)
        self.s2 = RegisterAlias("s2", self.d1, width=4, offset=0)
        self.s3 = RegisterAlias("s3", self.d1, width=4, offset=4)
        self.d2 = Register("d2", width=8)
        self.s4 = RegisterAlias("s4", self.d2, width=4, offset=0)
        self.s5 = RegisterAlias("s5", self.d2, width=4, offset=4)
        self.d3 = Register("d3", width=8)
        self.s6 = RegisterAlias("s6", self.d3, width=4, offset=0)
        self.s7 = RegisterAlias("s7", self.d3, width=4, offset=4)
        self.d4 = Register("d4", width=8)
        self.s8 = RegisterAlias("s8", self.d4, width=4, offset=0)
        self.s9 = RegisterAlias("s9", self.d4, width=4, offset=4)
        self.d5 = Register("d5", width=8)
        self.s10 = RegisterAlias("s10", self.d5, width=4, offset=0)
        self.s11 = RegisterAlias("s11", self.d5, width=4, offset=4)
        self.d6 = Register("d6", width=8)
        self.s12 = RegisterAlias("s12", self.d6, width=4, offset=0)
        self.s13 = RegisterAlias("s13", self.d6, width=4, offset=4)
        self.d7 = Register("d7", width=8)
        self.s14 = RegisterAlias("s14", self.d7, width=4, offset=0)
        self.s15 = RegisterAlias("s15", self.d7, width=4, offset=4)
        self.d8 = Register("d8", width=8)
        self.s16 = RegisterAlias("s16", self.d8, width=4, offset=0)
        self.s17 = RegisterAlias("s17", self.d8, width=4, offset=4)
        self.d9 = Register("d9", width=8)
        self.s18 = RegisterAlias("s18", self.d9, width=4, offset=0)
        self.s19 = RegisterAlias("s19", self.d9, width=4, offset=4)
        self.d10 = Register("d10", width=8)
        self.s20 = RegisterAlias("s20", self.d10, width=4, offset=0)
        self.s21 = RegisterAlias("s21", self.d10, width=4, offset=4)
        self.d11 = Register("d11", width=8)
        self.s22 = RegisterAlias("s22", self.d11, width=4, offset=0)
        self.s23 = RegisterAlias("s23", self.d11, width=4, offset=4)
        self.d12 = Register("d12", width=8)
        self.s24 = RegisterAlias("s24", self.d12, width=4, offset=0)
        self.s25 = RegisterAlias("s25", self.d12, width=4, offset=4)
        self.d13 = Register("d13", width=8)
        self.s26 = RegisterAlias("s26", self.d13, width=4, offset=0)
        self.s27 = RegisterAlias("s27", self.d13, width=4, offset=4)
        self.d14 = Register("d14", width=8)
        self.s28 = RegisterAlias("s28", self.d14, width=4, offset=0)
        self.s29 = RegisterAlias("s29", self.d14, width=4, offset=4)
        self.d15 = Register("d15", width=8)
        self.s30 = RegisterAlias("s30", self.d15, width=4, offset=0)
        self.s31 = RegisterAlias("s31", self.d15, width=4, offset=4)


class ARMCPUMixinVFPEL:
    """Mixin for little-endian ARM CPUs with VFP/NEON mixins

    This is one kind of floating-point extension
    which supports up to 128-bit scalar and SIMD vector operations.

    VFP and NEON are always optional extensions;
    The two can exist independently, and VFP can support either
    16 or 32 double registers.
    This is the maximal set of registers, assuming both are supported.
    """

    byteorder = "little"

    def __init__(self):
        super().__init__()
        # *** Floating-point Control Registers ***
        # Floating-point Status and Control Register
        self.fpscr = Register("fpscr", width=4)
        # Floating-point Exception Control Register
        self.fpexc = Register("fpexc", width=4)
        # Floating-point System ID Register
        self.fpsid = Register("fpsid", width=4)
        # Media and VFP Feature Register 0
        self.mvfr0 = Register("mvfr0", width=4)
        # Media and VFP Feature Register 1
        self.mvfr1 = Register("mvfr1", width=4)
        # *** Floating-point Registers ****
        self.q0 = Register("q0", width=16)
        self.d0 = RegisterAlias("d0", self.q0, width=8, offset=0)
        self.s0 = RegisterAlias("s0", self.q0, width=4, offset=0)
        self.s1 = RegisterAlias("s1", self.q0, width=4, offset=4)
        self.d1 = RegisterAlias("d1", self.q0, width=8, offset=8)
        self.s2 = RegisterAlias("s2", self.q0, width=4, offset=8)
        self.s3 = RegisterAlias("s3", self.q0, width=4, offset=12)
        self.q1 = Register("q1", width=16)
        self.d2 = RegisterAlias("d2", self.q1, width=8, offset=0)
        self.s4 = RegisterAlias("s4", self.q1, width=4, offset=0)
        self.s5 = RegisterAlias("s5", self.q1, width=4, offset=4)
        self.d3 = RegisterAlias("d3", self.q1, width=8, offset=8)
        self.s6 = RegisterAlias("s6", self.q1, width=4, offset=8)
        self.s7 = RegisterAlias("s7", self.q1, width=4, offset=12)
        self.q2 = Register("q2", width=16)
        self.d4 = RegisterAlias("d4", self.q2, width=8, offset=0)
        self.s8 = RegisterAlias("s8", self.q2, width=4, offset=0)
        self.s9 = RegisterAlias("s9", self.q2, width=4, offset=4)
        self.d5 = RegisterAlias("d5", self.q2, width=8, offset=8)
        self.s10 = RegisterAlias("s10", self.q2, width=4, offset=8)
        self.s11 = RegisterAlias("s11", self.q2, width=4, offset=12)
        self.q3 = Register("q3", width=16)
        self.d6 = RegisterAlias("d6", self.q3, width=8, offset=0)
        self.s12 = RegisterAlias("s12", self.q3, width=4, offset=0)
        self.s13 = RegisterAlias("s13", self.q3, width=4, offset=4)
        self.d7 = RegisterAlias("d7", self.q3, width=8, offset=8)
        self.s14 = RegisterAlias("s14", self.q3, width=4, offset=8)
        self.s15 = RegisterAlias("s15", self.q3, width=4, offset=12)
        self.q4 = Register("q4", width=16)
        self.d8 = RegisterAlias("d8", self.q4, width=8, offset=0)
        self.s16 = RegisterAlias("s16", self.q4, width=4, offset=0)
        self.s17 = RegisterAlias("s17", self.q4, width=4, offset=4)
        self.d9 = RegisterAlias("d9", self.q4, width=8, offset=8)
        self.s18 = RegisterAlias("s18", self.q4, width=4, offset=8)
        self.s19 = RegisterAlias("s19", self.q4, width=4, offset=12)
        self.q5 = Register("q5", width=16)
        self.d10 = RegisterAlias("d10", self.q5, width=8, offset=0)
        self.s20 = RegisterAlias("s20", self.q5, width=4, offset=0)
        self.s21 = RegisterAlias("s21", self.q5, width=4, offset=4)
        self.d11 = RegisterAlias("d11", self.q5, width=8, offset=8)
        self.s22 = RegisterAlias("s22", self.q5, width=4, offset=8)
        self.s23 = RegisterAlias("s23", self.q5, width=4, offset=12)
        self.q6 = Register("q6", width=16)
        self.d12 = RegisterAlias("d12", self.q6, width=8, offset=0)
        self.s24 = RegisterAlias("s24", self.q6, width=4, offset=0)
        self.s25 = RegisterAlias("s25", self.q6, width=4, offset=4)
        self.d13 = RegisterAlias("d13", self.q6, width=8, offset=8)
        self.s26 = RegisterAlias("s26", self.q6, width=4, offset=8)
        self.s27 = RegisterAlias("s27", self.q6, width=4, offset=12)
        self.q7 = Register("q7", width=16)
        self.d14 = RegisterAlias("d14", self.q7, width=8, offset=0)
        self.s28 = RegisterAlias("s28", self.q7, width=4, offset=0)
        self.s29 = RegisterAlias("s29", self.q7, width=4, offset=4)
        self.d15 = RegisterAlias("d15", self.q7, width=8, offset=8)
        self.s30 = RegisterAlias("s30", self.q7, width=4, offset=8)
        self.s31 = RegisterAlias("s31", self.q7, width=4, offset=12)
        # NOTE: This isn't a typo; there are only 32 single-precision sX registers
        # This does mean that only half the VFP register space can be used
        # for single-precision arithmetic.
        self.q8 = Register("q8", width=16)
        self.d16 = RegisterAlias("d16", self.q8, width=8, offset=0)
        self.d17 = RegisterAlias("d17", self.q8, width=8, offset=8)
        self.q9 = Register("q9", width=16)
        self.d18 = RegisterAlias("d18", self.q9, width=8, offset=0)
        self.d19 = RegisterAlias("d19", self.q9, width=8, offset=8)
        self.q10 = Register("q10", width=16)
        self.d20 = RegisterAlias("d20", self.q10, width=8, offset=0)
        self.d21 = RegisterAlias("d21", self.q10, width=8, offset=8)
        self.q11 = Register("q11", width=16)
        self.d22 = RegisterAlias("d22", self.q11, width=8, offset=0)
        self.d23 = RegisterAlias("d23", self.q11, width=8, offset=8)
        self.q12 = Register("q12", width=16)
        self.d24 = RegisterAlias("d24", self.q12, width=8, offset=0)
        self.d25 = RegisterAlias("d25", self.q12, width=8, offset=8)
        self.q13 = Register("q13", width=16)
        self.d26 = RegisterAlias("d26", self.q13, width=8, offset=0)
        self.d27 = RegisterAlias("d27", self.q13, width=8, offset=8)
        self.q14 = Register("q14", width=16)
        self.d28 = RegisterAlias("d28", self.q14, width=8, offset=0)
        self.d29 = RegisterAlias("d29", self.q14, width=8, offset=8)
        self.q15 = Register("q15", width=16)
        self.d30 = RegisterAlias("d30", self.q15, width=8, offset=0)
        self.d31 = RegisterAlias("d31", self.q15, width=8, offset=8)


class ARMv5TCPUState(ARMCPUMixinM, ARMCPUState):
    """CPU Model for ARMv5t little-endian"""

    mode = "v5t"
    byteorder = "little"


class ARMv6MCPUState(ARMCPUMixinFPEL, ARMCPUMixinM, ARMCPUState):
    """CPU Model for ARMv6-M little-endian"""

    mode = "v6m"


class ARMv7MCPUState(ARMCPUMixinFPEL, ARMCPUMixinM, ARMCPUState):
    """CPU Model for ARMv7-M little-endian"""

    mode = "v7m"


class ARMv7RCPUState(ARMCPUMixinVFPEL, ARMCPUMixinRA, ARMCPUState):
    """CPU Model for ARMv7-R little-endian"""

    # TODO: v7r and v7a have different MMUs, which I don't implement yet.
    mode = "v7r"


class ARMv7ACPUState(ARMCPUMixinVFPEL, ARMCPUMixinRA, ARMCPUState):
    """CPU Model for ARMv7-A little-endian"""

    mode = "v7a"
