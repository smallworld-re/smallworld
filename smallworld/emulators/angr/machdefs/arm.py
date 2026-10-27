import archinfo

from ....platforms import Architecture, Byteorder
from .machdef import AngrMachineDef


class ARMMachineDef(AngrMachineDef):
    def __init__(self):
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
            "r13": "sp",
            "lr": "lr",
            "r14": "lr",
            "pc": "pc",
            "r15": "pc",
        }


class ARMMachineMixinM:
    """Mixin class for M-series CPUs.

    The main difference between M and R/A
    is the available system status registers.
    """

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # *** Special Registers ***
                # Program Status Register
                # NOTE: PSR can be accessed through several masked views
                # via mrs/msr, which I'm not including:
                # - apsr: Just the condition flags; writable
                # - ipsr: Just exception information; read-only
                # - epsr: Just execution state info; reads as zero
                # - iapsr: apsr | ipsr
                # - eapsr: apsr | epsr
                # - iepsr: ipsr | epsr
                # - xpsr: apsr | ipsr | epsr
                "psr": "cpsr",
                # Exception Mask Register
                "primask": "primask",
                # Control register; includes a lot of flags.
                "control": "control",
                # *** Stack Pointer Bank ***
                # sp is actually an alias to one of these two.
                # Exactly which one depends on a bit in control.
                # Emulators that care should be careful when loading state.
                # Main Stack Pointer
                "msp": "msp",
                # Process Stack Pointer
                "psp": "psp",
            }
        )


class ARMMachineMixinMMainline(ARMMachineMixinM):
    """Mixin for ARMv7-M CPUs, which add priority masks to ARMv6-M"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # Base Priority Mask Register
                "basepri": "basepri",
                # Fault Mask Register
                "faultmask": "faultmask",
            }
        )


class ARMMachineMixinBanked:
    """Mixin for ARM CPUs with the classic banked-register model (non-M-profile)"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # *** Special Registers ***
                # Current Program Status Register
                # NOTE: CPSR has a few masked views
                # which I'm not including:
                # - apsr: Just the condition flags
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
                "sp_usr": "sp_usr",
                # User-mode Link Register
                "lr_usr": "lr_usr",
                # User-mode r8
                "r8_usr": "r8_usr",
                # User-mode r9
                "r9_usr": "r9_usr",
                # User-mode r10
                "r10_usr": "r10_usr",
                # User-mode r11
                "r11_usr": "r11_usr",
                # User-mode r12
                "r12_usr": "r12_usr",
                # Supervisor Stack Pointer
                "sp_svc": "sp_svc",
                # Supervisor Link Register
                "lr_svc": "lr_svc",
                # Supervisor Saved PSR
                "spsr_svc": "spsr_svc",
                # Abort-state Stack Pointer
                "sp_abt": "sp_abt",
                # Abort-state Link Register
                "lr_abt": "lr_abt",
                # Abort-state Saved PSR
                "spsr_abt": "spsr_abt",
                # Undefined-mode Stack Pointer
                "sp_und": "sp_und",
                # Undefined-mode Link Register
                "lr_und": "lr_und",
                # Undefined-mode Saved PSR
                "spsr_und": "spsr_und",
                # IRQ-mode Stack Pointer
                "sp_irq": "sp_irq",
                # IRQ-mode Link Register
                "lr_irq": "lr_irq",
                # IRQ-mode Saved PSR
                "spsr_irq": "spsr_irq",
                # FIQ-mode Stack Pointer
                "sp_fiq": "sp_fiq",
                # FIQ-mode Link Register
                "lr_fiq": "lr_fiq",
                # FIQ-mode Saved PSR
                "spsr_fiq": "spsr_fiq",
                # FIQ-mode r8
                "r8_fiq": "r8_fiq",
                # FIQ-mode r9
                "r9_fiq": "r9_fiq",
                # FIQ-mode r10
                "r10_fiq": "r10_fiq",
                # FIQ-mode r11
                "r11_fiq": "r11_fiq",
                # FIQ-mode r12
                "r12_fiq": "r12_fiq",
            }
        )


class ARMMachineMixinSecurity:
    """Mixin for CPUs with the Security Extensions (TrustZone)."""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # Monitor-mode Stack Pointer
                "sp_mon": "sp_mon",
                # Monitor-mode Link Register
                "lr_mon": "lr_mon",
                # Monitor-mode Saved PSR
                "spsr_mon": "spsr_mon",
                # Secure Configuration Register
                "scr": "scr",
                # Secure Debug Enable Register
                "sder": "sder",
                # Non-Secure Access Control Register
                "nsacr": "nsacr",
                # Monitor Vector Base Address Register
                "mvbar": "mvbar",
            }
        )


class ARMMachineMixinVirtualization:
    """Mixin for CPUs with the Virtualization Extensions."""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # Hypervisor Stack Pointer
                "sp_hyp": "sp_hyp",
                # Hypervisor Saved PSR
                "spsr_hyp": "spsr_hyp",
                # Hypervisor Exception Link Register
                # NOTE: Hyp mode has no banked lr; it uses lr_usr.
                "elr_hyp": "elr_hyp",
                # Hyp Configuration Register
                "hcr": "hcr",
                # Hyp Coprocessor Trap Register
                "hcptr": "hcptr",
                # Hyp System Trap Register
                "hstr": "hstr",
                # Hyp Debug Configuration Register
                "hdcr": "hdcr",
                # Hyp System Control Register
                "hsctlr": "hsctlr",
                # Hyp Vector Base Address Register
                "hvbar": "hvbar",
                # Hyp Translation Table Base Register
                "httbr": "httbr",
                # Hyp Translation Control Register
                "htcr": "htcr",
                # Virtualization Translation Table Base Register
                "vttbr": "vttbr",
                # Virtualization Translation Control Register
                "vtcr": "vtcr",
                # Hyp Syndrome Register
                "hsr": "hsr",
                # Hyp Data Fault Address Register
                "hdfar": "hdfar",
                # Hyp Instruction Fault Address Register
                "hifar": "hifar",
                # Hyp IPA Fault Address Register
                "hpfar": "hpfar",
                # Hyp Software Thread ID Register
                "htpidr": "htpidr",
                # Hyp Memory Attribute Indirection Register 0
                "hmair0": "hmair0",
                # Hyp Memory Attribute Indirection Register 1
                "hmair1": "hmair1",
                # Virtualization Processor ID Register
                "vpidr": "vpidr",
                # Virtualization Multiprocessor ID Register
                "vmpidr": "vmpidr",
                # Virtual Offset Register
                "cntvoff": "cntvoff",
                # Timer PL2 Control Register
                "cnthctl": "cnthctl",
                # PL2 Physical Timer Control Register
                "cnthp_ctl": "cnthp_ctl",
                # PL2 Physical Timer CompareValue Register
                "cnthp_cval": "cnthp_cval",
            }
        )


class ARMMachineMixinV5SystemControl:
    """Mixin for ARMv5 CPUs with a cp15 system control coprocessor"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # Main ID Register
                "midr": "midr",
                # Cache Type Register
                "ctr": "ctr",
                # System Control Register
                "sctlr": "sctlr",
                # Translation Table Base Register
                "ttbr": "ttbr",
                # Domain Access Control Register
                "dacr": "dacr",
                # Fault Status Register
                "fsr": "fsr",
                # Fault Address Register
                "far": "far",
                # FCSE Process ID Register
                "fcseidr": "fcseidr",
            }
        )


class ARMMachineMixinV6SystemControl:
    """Mixin for ARMv6 CPUs with a cp15 system control coprocessor"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # Main ID Register
                "midr": "midr",
                # Cache Type Register
                "ctr": "ctr",
                # System Control Register
                "sctlr": "sctlr",
                # Auxiliary Control Register
                "actlr": "actlr",
                # Coprocessor Access Control Register
                "cpacr": "cpacr",
                # Translation Table Base Register 0
                "ttbr0": "ttbr0",
                # Translation Table Base Register 1
                "ttbr1": "ttbr1",
                # Translation Table Base Control Register
                "ttbcr": "ttbcr",
                # Domain Access Control Register
                "dacr": "dacr",
                # Data Fault Status Register
                "dfsr": "dfsr",
                # Instruction Fault Status Register
                "ifsr": "ifsr",
                # Data Fault Address Register
                "dfar": "dfar",
                # Watchpoint Fault Address Register
                "wfar": "wfar",
                # Instruction Fault Address Register
                "ifar": "ifar",
                # Physical Address Register
                "par": "par",
                # Primary Region Remap Register
                "prrr": "prrr",
                # Normal Memory Remap Register
                "nmrr": "nmrr",
                # Vector Base Address Register
                "vbar": "vbar",
                # FCSE Process ID Register
                "fcseidr": "fcseidr",
                # Context ID Register
                "contextidr": "contextidr",
                # User Read/Write Thread ID Register
                "tpidrurw": "tpidrurw",
                # User Read-Only Thread ID Register
                "tpidruro": "tpidruro",
                # PL1-only Thread ID Register
                "tpidrprw": "tpidrprw",
            }
        )


class ARMMachineMixinV7SystemControl:
    """Mixin for the cp15 registers common to ARMv7-A and ARMv7-R"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # Main ID Register
                "midr": "midr",
                # Cache Type Register
                "ctr": "ctr",
                # Multiprocessor Affinity Register
                "mpidr": "mpidr",
                # System Control Register
                "sctlr": "sctlr",
                # Auxiliary Control Register
                "actlr": "actlr",
                # Coprocessor Access Control Register
                "cpacr": "cpacr",
                # Cache Size Selection Register
                "csselr": "csselr",
                # Data Fault Status Register
                "dfsr": "dfsr",
                # Instruction Fault Status Register
                "ifsr": "ifsr",
                # Data Fault Address Register
                "dfar": "dfar",
                # Instruction Fault Address Register
                "ifar": "ifar",
                # Context ID Register
                "contextidr": "contextidr",
                # User Read/Write Thread ID Register
                "tpidrurw": "tpidrurw",
                # User Read-Only Thread ID Register
                "tpidruro": "tpidruro",
                # PL1-only Thread ID Register
                "tpidrprw": "tpidrprw",
            }
        )


class ARMMachineMixinPMSA:
    """Mixin for ARMv7 CPUs with an MPU (the R-series)"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # MPU Region Number Register
                "rgnr": "rgnr",
                # Data Region Base Address Register
                "drbar": "drbar",
                # Data Region Size and Enable Register
                "drsr": "drsr",
                # Data Region Access Control Register
                "dracr": "dracr",
            }
        )


class ARMMachineMixinVMSA:
    """Mixin for ARMv7 CPUs with an MMU and the Large Physical Address Extension"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # Translation Table Base Register 0
                "ttbr0": "ttbr0",
                # Translation Table Base Register 1
                "ttbr1": "ttbr1",
                # Translation Table Base Control Register
                "ttbcr": "ttbcr",
                # Domain Access Control Register
                "dacr": "dacr",
                # Physical Address Register
                "par": "par",
                # Primary Region Remap Register
                "prrr": "prrr",
                # Normal Memory Remap Register
                "nmrr": "nmrr",
                # Vector Base Address Register
                "vbar": "vbar",
            }
        )


class ARMMachineMixinGenericTimer:
    """Mixin for ARMv7 CPUs with the Generic Timer Extension"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # Counter Frequency Register
                "cntfrq": "cntfrq",
                # Timer PL1 Control Register
                "cntkctl": "cntkctl",
                # Physical Count Register
                "cntpct": "cntpct",
                # Virtual Count Register
                "cntvct": "cntvct",
                # PL1 Physical Timer Control Register
                "cntp_ctl": "cntp_ctl",
                # PL1 Physical Timer CompareValue Register
                "cntp_cval": "cntp_cval",
                # Virtual Timer Control Register
                "cntv_ctl": "cntv_ctl",
                # Virtual Timer CompareValue Register
                "cntv_cval": "cntv_cval",
            }
        )


class ARMMachineMixinFPD16:
    """Mixin for ARM machine models with a 16-register FPU

    The register file shared by every 16-register ARM FPU:
    d0-d15, aliased as s0-s31, and FPSCR.
    """

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # *** Floating point control registers ***
                # Floating-point Status and Control Register
                "fpscr": "fpscr",
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


class ARMMachineMixinFP(ARMMachineMixinFPD16):
    """Mixin for ARM CPUs with FP extensions

    This is one kind of floating-point extension
    which offers 64-bit scalar operations.
    """

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # Floating-point Exception Control Register
                "fpexc": None,
                # Floating-point System ID Register
                "fpsid": None,
                # Media and VFP Feature Register 0
                "mvfr0": None,
                # Media and VFP Feature Register 1
                "mvfr1": None,
            }
        )


class ARMMachineMixinVFPv2(ARMMachineMixinFP):
    """Mixin for little-endian ARM CPUs with VFPv2"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # Floating-point Instruction Register
                "fpinst": "fpinst",
                # Floating-point Instruction Register 2
                "fpinst2": "fpinst2",
            }
        )


class ARMMachineMixinVFPEL:
    """Mixin for ARM CPUs with 32-register VFP and NEON

    archinfo has no q registers, but lays out d0-d31 contiguously,
    so each qN spans d(2N) and d(2N+1).
    """

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # *** Floating-point Control Registers ***
                # Floating-point Status and Control Register
                "fpscr": "fpscr",
                # Floating-point Exception Control Register
                "fpexc": None,
                # Floating-point System ID Register
                "fpsid": None,
                # Media and VFP Feature Register 0
                "mvfr0": None,
                # Media and VFP Feature Register 1
                "mvfr1": None,
                # *** Floating-point Registers ****
                "q0": ("d0", 16),
                "d0": "d0",
                "s0": "s0",
                "s1": "s1",
                "d1": "d1",
                "s2": "s2",
                "s3": "s3",
                "q1": ("d2", 16),
                "d2": "d2",
                "s4": "s4",
                "s5": "s5",
                "d3": "d3",
                "s6": "s6",
                "s7": "s7",
                "q2": ("d4", 16),
                "d4": "d4",
                "s8": "s8",
                "s9": "s9",
                "d5": "d5",
                "s10": "s10",
                "s11": "s11",
                "q3": ("d6", 16),
                "d6": "d6",
                "s12": "s12",
                "s13": "s13",
                "d7": "d7",
                "s14": "s14",
                "s15": "s15",
                "q4": ("d8", 16),
                "d8": "d8",
                "s16": "s16",
                "s17": "s17",
                "d9": "d9",
                "s18": "s18",
                "s19": "s19",
                "q5": ("d10", 16),
                "d10": "d10",
                "s20": "s20",
                "s21": "s21",
                "d11": "d11",
                "s22": "s22",
                "s23": "s23",
                "q6": ("d12", 16),
                "d12": "d12",
                "s24": "s24",
                "s25": "s25",
                "d13": "d13",
                "s26": "s26",
                "s27": "s27",
                "q7": ("d14", 16),
                "d14": "d14",
                "s28": "s28",
                "s29": "s29",
                "d15": "d15",
                "s30": "s30",
                "s31": "s31",
                # NOTE: This isn't a typo; there are only 32 single-precision sX registers
                # This does mean that only half the VFP register space can be used
                # for single-precision arithmetic.
                "q8": ("d16", 16),
                "d16": "d16",
                "d17": "d17",
                "q9": ("d18", 16),
                "d18": "d18",
                "d19": "d19",
                "q10": ("d20", 16),
                "d20": "d20",
                "d21": "d21",
                "q11": ("d22", 16),
                "d22": "d22",
                "d23": "d23",
                "q12": ("d24", 16),
                "d24": "d24",
                "d25": "d25",
                "q13": ("d26", 16),
                "d26": "d26",
                "d27": "d27",
                "q14": ("d28", 16),
                "d28": "d28",
                "d29": "d29",
                "q15": ("d30", 16),
                "d30": "d30",
                "d31": "d31",
            }
        )


class ARMMachineMixinVFPv8(ARMMachineMixinVFPEL):
    """Mixin for little-endian ARMv8 AArch32 CPUs with FP and Advanced SIMD"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # Media and VFP Feature Register 2
                "mvfr2": "mvfr2",
            }
        )


class ARMMachineMixinPMSAv8:
    """Mixin for ARMv8-R CPUs with the PMSAv8-32 MPU"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # Protection Region Selection Register
                "prselr": "prselr",
                # Protection Region Base Address Register
                "prbar": "prbar",
                # Protection Region Limit Address Register
                "prlar": "prlar",
                # Memory Attribute Indirection Register 0
                "mair0": "mair0",
                # Memory Attribute Indirection Register 1
                "mair1": "mair1",
                # Vector Base Address Register
                "vbar": "vbar",
            }
        )


class ARMMachineMixinV8RHypervisor:
    """Mixin for ARMv8-R CPUs' Hypervisor mode (EL2)"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # Hypervisor Stack Pointer
                "sp_hyp": "sp_hyp",
                # Hypervisor Saved PSR
                "spsr_hyp": "spsr_hyp",
                # Hypervisor Exception Link Register
                # NOTE: Hyp mode has no banked lr; it uses lr_usr.
                "elr_hyp": "elr_hyp",
                # Hyp Configuration Register
                "hcr": "hcr",
                # Hyp Coprocessor Trap Register
                "hcptr": "hcptr",
                # Hyp System Trap Register
                "hstr": "hstr",
                # Hyp Debug Configuration Register
                "hdcr": "hdcr",
                # Hyp System Control Register
                "hsctlr": "hsctlr",
                # Hyp Vector Base Address Register
                "hvbar": "hvbar",
                # Hyp Syndrome Register
                "hsr": "hsr",
                # Hyp Data Fault Address Register
                "hdfar": "hdfar",
                # Hyp Instruction Fault Address Register
                "hifar": "hifar",
                # Hyp Software Thread ID Register
                "htpidr": "htpidr",
                # Hyp Memory Attribute Indirection Register 0
                "hmair0": "hmair0",
                # Hyp Memory Attribute Indirection Register 1
                "hmair1": "hmair1",
                # Virtualization Processor ID Register
                "vpidr": "vpidr",
                # Virtualization Multiprocessor ID Register
                "vmpidr": "vmpidr",
                # Hyp Protection Region Selection Register
                "hprselr": "hprselr",
                # Hyp Protection Region Base Address Register
                "hprbar": "hprbar",
                # Hyp Protection Region Limit Address Register
                "hprlar": "hprlar",
                # Virtual Offset Register
                "cntvoff": "cntvoff",
                # Timer PL2 Control Register
                "cnthctl": "cnthctl",
                # PL2 Physical Timer Control Register
                "cnthp_ctl": "cnthp_ctl",
                # PL2 Physical Timer CompareValue Register
                "cnthp_cval": "cnthp_cval",
            }
        )


class ARMMachineMixinV8MMainline(ARMMachineMixinMMainline):
    """Abstract class for ARMv8-M Mainline CPUs."""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # Main Stack Pointer Limit Register
                "msplim": "msplim",
                # Process Stack Pointer Limit Register
                "psplim": "psplim",
            }
        )


class ARMv4MachineDef(
    ARMMachineMixinV5SystemControl, ARMMachineMixinBanked, ARMMachineDef
):
    angr_arch = archinfo.arch_arm.ArchARMEL()
    arch = Architecture.ARM_V4
    byteorder = Byteorder.LITTLE


class ARMv4TMachineDef(
    ARMMachineMixinV5SystemControl, ARMMachineMixinBanked, ARMMachineDef
):
    angr_arch = archinfo.arch_arm.ArchARMEL()
    arch = Architecture.ARM_V4T
    byteorder = Byteorder.LITTLE


class ARMv5TMachineDef(
    ARMMachineMixinV5SystemControl, ARMMachineMixinBanked, ARMMachineDef
):
    angr_arch = archinfo.arch_arm.ArchARMEL()
    arch = Architecture.ARM_V5T
    byteorder = Byteorder.LITTLE


# Big-endian ARMv4 and ARMv5 are BE32: archinfo's big-endian ARM fetches
# instructions big-endian too.


class ARMv4BEMachineDef(ARMv4MachineDef):
    angr_arch = archinfo.arch_arm.ArchARMEL(archinfo.Endness.BE)
    byteorder = Byteorder.BIG


class ARMv4TBEMachineDef(ARMv4TMachineDef):
    angr_arch = archinfo.arch_arm.ArchARMEL(archinfo.Endness.BE)
    byteorder = Byteorder.BIG


class ARMv5TBEMachineDef(ARMv5TMachineDef):
    angr_arch = archinfo.arch_arm.ArchARMEL(archinfo.Endness.BE)
    byteorder = Byteorder.BIG


class ARMv6KMachineDef(
    ARMMachineMixinVFPv2,
    ARMMachineMixinSecurity,
    ARMMachineMixinV6SystemControl,
    ARMMachineMixinBanked,
    ARMMachineDef,
):
    angr_arch = archinfo.arch_arm.ArchARMEL()
    arch = Architecture.ARM_V6K
    byteorder = Byteorder.LITTLE


class ARMv6MMachineDef(ARMMachineMixinM, ARMMachineDef):
    # M-profile is Thumb-only.
    angr_arch = archinfo.arch_arm.ArchARMCortexM()
    arch = Architecture.ARM_V6M
    byteorder = Byteorder.LITTLE
    is_thumb = True


class ARMv6MThumbMachineDef(ARMv6MMachineDef):
    arch = Architecture.ARM_V6M_THUMB


class ARMv7MMachineDef(ARMMachineMixinMMainline, ARMMachineDef):
    # M-profile is Thumb-only.
    angr_arch = archinfo.arch_arm.ArchARMCortexM()
    arch = Architecture.ARM_V7M
    byteorder = Byteorder.LITTLE
    is_thumb = True


class ARMv7EMMachineDef(ARMMachineMixinFPD16, ARMMachineMixinMMainline, ARMMachineDef):
    # M-profile is Thumb-only. archinfo's Cortex-M arch has the FPU registers.
    angr_arch = archinfo.arch_arm.ArchARMCortexM()
    arch = Architecture.ARM_V7EM
    byteorder = Byteorder.LITTLE
    is_thumb = True


class ARMv7AMachineDef(
    ARMMachineMixinVFPEL,
    ARMMachineMixinVirtualization,
    ARMMachineMixinSecurity,
    ARMMachineMixinGenericTimer,
    ARMMachineMixinVMSA,
    ARMMachineMixinV7SystemControl,
    ARMMachineMixinBanked,
    ARMMachineDef,
):
    # TODO: This is a user-space integer only model
    angr_arch = archinfo.arch_arm.ArchARMHF()
    arch = Architecture.ARM_V7A
    byteorder = Byteorder.LITTLE


class ARMv8AMachineDef(
    ARMMachineMixinVFPv8,
    ARMMachineMixinVirtualization,
    ARMMachineMixinSecurity,
    ARMMachineMixinGenericTimer,
    ARMMachineMixinVMSA,
    ARMMachineMixinV7SystemControl,
    ARMMachineMixinBanked,
    ARMMachineDef,
):
    angr_arch = archinfo.arch_arm.ArchARMHF()
    arch = Architecture.ARM_V8A
    byteorder = Byteorder.LITTLE


class ARMv8RMachineDef(
    ARMMachineMixinVFPv8,
    ARMMachineMixinV8RHypervisor,
    ARMMachineMixinGenericTimer,
    ARMMachineMixinPMSAv8,
    ARMMachineMixinV7SystemControl,
    ARMMachineMixinBanked,
    ARMMachineDef,
):
    angr_arch = archinfo.arch_arm.ArchARMHF()
    arch = Architecture.ARM_V8R
    byteorder = Byteorder.LITTLE


class ARMv8MMachineDef(ARMMachineMixinV8MMainline, ARMMachineDef):
    # M-profile is Thumb-only.
    angr_arch = archinfo.arch_arm.ArchARMCortexM()
    arch = Architecture.ARM_V8M
    byteorder = Byteorder.LITTLE
    is_thumb = True


class ARMv7RMachineDef(
    ARMMachineMixinFP,
    ARMMachineMixinPMSA,
    ARMMachineMixinV7SystemControl,
    ARMMachineMixinBanked,
    ARMMachineDef,
):
    angr_arch = archinfo.arch_arm.ArchARMHF()
    arch = Architecture.ARM_V7R
    byteorder = Byteorder.LITTLE
