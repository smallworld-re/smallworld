from ....platforms import Architecture, Byteorder
from .machdef import PcodeMachineDef


class ARMMachineDef(PcodeMachineDef):
    pc_reg = "pc"

    def __init__(self):
        super().__init__()
        self._registers = {
            # *** General-purpose registers ***
            "r0": "r0",
            "r1": "r1",
            "r2": "r2",
            "r3": "r3",
            "r4": "r4",
            "r5": "r5",
            "r6": "r6",
            "r7": "r7",
            "r8": "r8",
            # r9 doubles as the Static base pointer
            "r9": "r9",
            "sb": "sb",
            # r10 doubles as the Stack Limit pointer
            "r10": "r10",
            "sl": "sl",
            # r11 doubles as the Frame Pointer, if desired.
            "r11": "r11",
            "fp": "fp",
            # r12 doubles as the Intra-call scratch register
            "r12": "r12",
            "ip": "ip",
            "sp": "sp",
            "lr": "lr",
            "pc": "pc",
        }


class ARMMachineMixinM:
    """Mixin for ARM series M CPUs"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
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
                # NOTE: Ghidra has a single ARM32 model that appears to focus on the A series.
                # I'd avoid doing privileged stuff on the M series.
                "psr": "cpsr",
                # Exception Mask Register
                "primask": None,
                # Base Priority Mask Register
                "basepri": None,
                # Fault Mask Register
                "faultmask": None,
                # Control register; includes a lot of flags.
                "control": None,
                # *** Stack Pointer Bank ***
                # sp is actually an alias to one of these two.
                # Exactly which one depends on a bit in control.
                # Emulators that care should be careful when loading state.
                # Main Stack Pointer
                "msp": None,
                # Process Stack Pointer
                "psp": None,
            }
        )


class ARMMachineMixinRA:
    """Mixin for ARM series A and R CPUs"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # *** Special Registers ***
                # Current Program Status Register
                # NOTE: CPSR can be accessed through several masked aliases.
                # These are read-only, so I'm not including them.
                # - isetstate: Just includes instruction set control bits
                # - itstate: Just includes state bits for Thumb IT instruction
                "cpsr": "cpsr",
                # Saved Program Status Register
                "spsr": "spsr",
                # *** Register Banks ***
                # sp, lr, and spsr are actually aliases to one of these.
                # Which one they reference depends on execution mode.
                # Emulators that care should be careful when loading state.
                # NOTE: Use User-mode copies of registers unless the mode has its own.
                # User-mode Stack Pointer
                "sp_usr": None,
                # User-mode Link Register
                "lr_usr": None,
                # User-mode r8
                "r8_usr": None,
                # User-mode r9
                "r9_usr": None,
                # User-mode r10
                "r10_usr": None,
                # User-mode r11
                "r11_usr": None,
                # User-mode r12
                "r12_usr": None,
                # Hypervisor Stack Pointer
                "sp_hyp": None,
                # Hypervisor Saved PSR
                "spsr_hyp": None,
                # Hypervisor Exception Link Register
                # NOTE: None,
                "elr_hyp": None,
                # Supervisor Stack Pointer
                "sp_svc": None,
                # Supervisor Link Register
                "lr_svc": None,
                # Supervisor Saved PSR
                "spsr_svc": None,
                # Abort-state Stack Pointer
                "sp_abt": None,
                # Abort-state Link Register
                "lr_abt": None,
                # Abort-state Saved PSR
                "spsr_abt": None,
                # Undefined-mode Stack Pointer
                "sp_und": None,
                # Undefined-mode Link Register
                "lr_und": None,
                # Undefined-mode Saved PSR
                "spsr_und": None,
                # Monitor-mode Stack Pointer
                "sp_mon": None,
                # Monitor-mode Link Register
                "lr_mon": None,
                # Monitor-mode Saved PSR
                "spsr_mon": None,
                # IRQ-mode Stack Pointer
                "sp_irq": None,
                # IRQ-mode Link Register
                "lr_irq": None,
                # IRQ-mode Saved PSR
                "spsr_irq": None,
                # FIQ-mode Stack Pointer
                "sp_fiq": None,
                # FIQ-mode Link Register
                "lr_fiq": None,
                # FIQ-mode Saved PSR
                "spsr_fiq": None,
                # FIQ-mode r8
                "r8_fiq": None,
                # FIQ-mode r9
                "r9_fiq": None,
                # FIQ-mode r10
                "r10_fiq": None,
                # FIQ-mode r11
                "r11_fiq": None,
                # FIQ-mode r12
                "r12_fiq": None,
            }
        )


class ARMMachineMixinFP:
    """Mixin for ARM CPUs with FP extensions

    This is one kind of floating-point extension
    which offers 64-bit scalar operations.
    """

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # *** Floating point control registers ***
                # Floating-point Status and Control Register
                "fpscr": "fpscr",
                # Floating-point Exception Control Register
                "fpexc": "fpexc",
                # Floating-point System ID Register
                "fpsid": "fpsid",
                # Media and VFP Feature Register 0
                "mvfr0": "mvfr0",
                # Media and VFP Feature Register 1
                "mvfr1": "mvfr1",
                # *** Floating point registers ***
                "d0": "d0",
                "s0": "s0",
                "s1": "s1",
                "d1": "d1",
                "s2": "s2",
                "s3": "s3",
                "d2": "d2",
                "s4": "s4",
                "s5": "s5",
                "d3": "d3",
                "s6": "s6",
                "s7": "s7",
                "d4": "d4",
                "s8": "s8",
                "s9": "s9",
                "d5": "d5",
                "s10": "s10",
                "s11": "s11",
                "d6": "d6",
                "s12": "s12",
                "s13": "s13",
                "d7": "d7",
                "s14": "s14",
                "s15": "s15",
                "d8": "d8",
                "s16": "s16",
                "s17": "s17",
                "d9": "d9",
                "s18": "s18",
                "s19": "s19",
                "d10": "d10",
                "s20": "s20",
                "s21": "s21",
                "d11": "d11",
                "s22": "s22",
                "s23": "s23",
                "d12": "d12",
                "s24": "s24",
                "s25": "s25",
                "d13": "d13",
                "s26": "s26",
                "s27": "s27",
                "d14": "d14",
                "s28": "s28",
                "s29": "s29",
                "d15": "d15",
                "s30": "s30",
                "s31": "s31",
            }
        )


class ARMMachineMixinVFPEL:
    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # *** Floating-point Control Registers ***
                # Floating-point Status and Control Register
                "fpscr": "fpscr",
                # Floating-point Exception Control Register
                "fpexc": "fpexc",
                # Floating-point System ID Register
                "fpsid": "fpsid",
                # Media and VFP Feature Register 0
                "mvfr0": "mvfr0",
                # Media and VFP Feature Register 1
                "mvfr1": "mvfr1",
                # *** Floating-point Registers ****
                "q0": "q0",
                "d0": "d0",
                "s0": "s0",
                "s1": "s1",
                "d1": "d1",
                "s2": "s2",
                "s3": "s3",
                "q1": "q1",
                "d2": "d2",
                "s4": "s4",
                "s5": "s5",
                "d3": "d3",
                "s6": "s6",
                "s7": "s7",
                "q2": "q2",
                "d4": "d4",
                "s8": "s8",
                "s9": "s9",
                "d5": "d5",
                "s10": "s10",
                "s11": "s11",
                "q3": "q3",
                "d6": "d6",
                "s12": "s12",
                "s13": "s13",
                "d7": "d7",
                "s14": "s14",
                "s15": "s15",
                "q4": "q4",
                "d8": "d8",
                "s16": "s16",
                "s17": "s17",
                "d9": "d9",
                "s18": "s18",
                "s19": "s19",
                "q5": "q5",
                "d10": "d10",
                "s20": "s20",
                "s21": "s21",
                "d11": "d11",
                "s22": "s22",
                "s23": "s23",
                "q6": "q6",
                "d12": "d12",
                "s24": "s24",
                "s25": "s25",
                "d13": "d13",
                "s26": "s26",
                "s27": "s27",
                "q7": "q7",
                "d14": "d14",
                "s28": "s28",
                "s29": "s29",
                "d15": "d15",
                "s30": "s30",
                "s31": "s31",
                # NOTE: This isn't a typo; there are only 32 single-precision sX registers
                # This does mean that only half the VFP register space can be used
                # for single-precision arithmetic.
                "q8": "q8",
                "d16": "d16",
                "d17": "d17",
                "q9": "q9",
                "d18": "d18",
                "d19": "d19",
                "q10": "q10",
                "d20": "d20",
                "d21": "d21",
                "q11": "q11",
                "d22": "d22",
                "d23": "d23",
                "q12": "q12",
                "d24": "d24",
                "d25": "d25",
                "q13": "q13",
                "d26": "d26",
                "d27": "d27",
                "q14": "q14",
                "d28": "d28",
                "d29": "d29",
                "q15": "q15",
                "d30": "d30",
                "d31": "d31",
            }
        )


class ARMv5TMachineDef(ARMMachineMixinM, ARMMachineDef):
    arch = Architecture.ARM_V5T
    byteorder = Byteorder.LITTLE
    language_id = "ARM:LE:32:v5t"


class ARMv6MMachineDef(ARMMachineMixinM, ARMMachineDef):
    arch = Architecture.ARM_V6M
    byteorder = Byteorder.LITTLE
    language_id = "ARM:LE:32:v6"


class ARMv7MMachineDef(ARMMachineMixinFP, ARMMachineMixinM, ARMMachineDef):
    arch = Architecture.ARM_V7M
    byteorder = Byteorder.LITTLE
    language_id = "ARM:LE:32:v7"


class ARMv7AMachineDef(ARMMachineMixinVFPEL, ARMMachineMixinRA, ARMMachineDef):
    arch = Architecture.ARM_V7A
    byteorder = Byteorder.LITTLE
    language_id = "ARM:LE:32:v7"
