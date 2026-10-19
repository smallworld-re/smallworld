import typing

import capstone

from ..platforms import Architecture, Byteorder
from .platformdef import PlatformDef, RegisterAliasDef, RegisterDef

#: Ghidra's 32-bit ARM model exposes the condition flags as four one-bit
#: registers. SmallWorld models them as fields of the program status
#: register, which the M-profile calls psr and every other profile cpsr -- hence
#: one map per mixin, below.
#:
#: Mapping them costs some precision: Ghidra routes every data-processing
#: operand through the barrel shifter and seeds a scratch from the carry, so
#: a plain `add` or an immediate `lsl` reports a *spurious* read of cy (or
#: ov) and now therefore of the status register. It is not separable from a
#: real carry read -- `add` and `adc` are identical in p-code -- and Capstone
#: cannot arbitrate, as it misses the flag reads of `beq` and of
#: conditionally executed instructions entirely. The trade is deliberate:
#: unmapped, `cmp` reported writing nothing at all and no conditional branch
#: read a flag, which understates real dependencies; over-reporting a read
#: is the safer direction. See tests/pcode_use_def/README.md.
_ARM_FLAGS = ("ng", "zr", "cy", "ov")


def _flag_aliases(register: str) -> typing.Dict[str, str]:
    return {flag: register for flag in _ARM_FLAGS}


class ARMPlatformDef(PlatformDef):
    """Base class for ARM 32-bit platform definitions

    All ARM CPUs share the same basic registers,
    but there are at least two dimensions of difference:
    M-series vs A/R series, and FPU model.
    """

    byteorder = Byteorder.LITTLE

    address_size = 4

    capstone_arch = capstone.CS_ARCH_ARM
    capstone_mode = capstone.CS_MODE_ARM

    conditional_branch_mnemonics = {
        # Conditional branch
        "beq",
        "bne",
        "bcs",
        "bhs",
        "bcc",
        "blo",
        "bmi",
        "bpl",
        "bvs",
        "bvc",
        "bhi",
        "bls",
        "bge",
        "blt",
        "bgt",
        "ble",
        # Compare and branch on zero/non-zero
        "cbz",
        "cbnz",
    }

    # cbz/cbnz test a register directly against zero rather than the condition
    # flags, so they are compare-branches (mirroring AMD64's jrcxz/jecxz/jcxz,
    # which also appear in both sets).
    compare_branch_mnemonics = {
        "cbz",
        "cbnz",
    }

    pc_register = "pc"
    sp_register = "sp"

    # NOTE: r9, r10, r11, and r12 technically have special purposes,
    # but they're optional.
    general_purpose_registers = [f"r{i}" for i in range(0, 13)]

    @property
    def registers(self) -> typing.Dict[str, RegisterDef]:
        return self._registers

    @property
    def compare_mnemonics(self) -> typing.Set[str]:
        return self._compare_mnemonics

    def __init__(self):
        super().__init__()
        self._compare_mnemonics = {
            # Integer comparison
            "cmp",
            "cmn",
            "tst",
            # Conditional integer comparison
            "cmpeq",
            "cmpne",
            "cmpcs",
            "cmphs",
            "cmpcc",
            "cmplo",
            "cmpmi",
            "cmppl",
            "cmpvs",
            "cmpvc",
            "cmphi",
            "cmpls",
            "cmpge",
            "cmplt",
            "cmpgt",
            "cmple",
            "cmneq",
            "cmnne",
            "cmncs",
            "cmnhs",
            "cmncc",
            "cmnlo",
            "cmnmi",
            "cmnpl",
            "cmnvs",
            "cmnvc",
            "cmnhi",
            "cmnls",
            "cmnge",
            "cmnlt",
            "cmngt",
            "cmnle",
            "tsteq",
            "tstne",
            "tstcs",
            "tsths",
            "tstcc",
            "tstlo",
            "tstmi",
            "tstpl",
            "tstvs",
            "tstvc",
            "tsthi",
            "tstls",
            "tstge",
            "tstlt",
            "tstgt",
            "tstle",
        }
        self._registers = {
            # *** General-purpose registers ***
            "r0": RegisterDef(name="r0", size=4),
            "r1": RegisterDef(name="r1", size=4),
            "r2": RegisterDef(name="r2", size=4),
            "r3": RegisterDef(name="r3", size=4),
            "r4": RegisterDef(name="r4", size=4),
            "r5": RegisterDef(name="r5", size=4),
            "r6": RegisterDef(name="r6", size=4),
            "r7": RegisterDef(name="r7", size=4),
            "r8": RegisterDef(name="r8", size=4),
            # r9 doubles as the Static base pointer
            "r9": RegisterDef(name="r9", size=4),
            "sb": RegisterAliasDef(name="sb", parent="r9", size=4, offset=0),
            # r10 doubles as the Stack Limit pointer
            "r10": RegisterDef(name="r10", size=4),
            "sl": RegisterAliasDef(name="sl", parent="r10", size=4, offset=0),
            # r11 doubles as the Frame Pointer, if desired.
            "r11": RegisterDef(name="r11", size=4),
            "fp": RegisterAliasDef(name="fp", parent="r11", size=4, offset=0),
            # r12 doubles as the Intra-call scratch register
            "r12": RegisterDef(name="r12", size=4),
            "ip": RegisterAliasDef(name="ip", parent="r12", size=4, offset=0),
            # sp doubles as r13
            "sp": RegisterDef(name="sp", size=4),
            "r13": RegisterAliasDef(name="r13", parent="sp", size=4, offset=0),
            # lr doubles as r14
            "lr": RegisterDef(name="lr", size=4),
            "r14": RegisterAliasDef(name="r14", parent="lr", size=4, offset=0),
            # pc doubles as r15
            "pc": RegisterDef(name="pc", size=4),
            "r15": RegisterAliasDef(name="r15", parent="pc", size=4, offset=0),
        }


class ARMPlatformMixinM:
    """Abstract class for M-profile CPUs (ARMv6-M baseline).

    The M-series CPUs are built for embedded applications,
    and have an extremely simplified privilege model,
    and don't often have an MMU.

    This is the register set common to every M-profile CPU;
    ARMv7-M adds more priority masks
    (see :class:`ARMPlatformMixinMMainline`).
    """

    ghidra_register_aliases = _flag_aliases("psr")
    status_register: typing.Optional[str] = "psr"

    def __init__(self):
        super().__init__()
        self._registers |= {
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
            "psr": RegisterDef(name="psr", size=4),
            # Exception Mask Register
            "primask": RegisterDef(name="primask", size=4),
            # Control register; includes a lot of flags.
            "control": RegisterDef(name="control", size=4),
            # *** Stack Pointer Bank ***
            # sp is actually an alias to one of these two.
            # Exactly which one depends on a bit in control.
            # Emulators that care should be careful when loading state.
            # Main Stack Pointer
            "msp": RegisterDef(name="msp", size=4),
            # Process Stack Pointer
            "psp": RegisterDef(name="psp", size=4),
        }


class ARMPlatformMixinMMainline(ARMPlatformMixinM):
    """Abstract class for ARMv7-M CPUs.

    ARMv7-M adds priority-based exception masking
    on top of the ARMv6-M baseline.
    """

    def __init__(self):
        super().__init__()
        self._registers |= {
            # Base Priority Mask Register
            "basepri": RegisterDef(name="basepri", size=4),
            # Fault Mask Register
            "faultmask": RegisterDef(name="faultmask", size=4),
        }


class ARMPlatformMixinBanked:
    """Abstract class for CPUs with the classic banked-register model.

    This covers every non-M-profile CPU from ARMv4 on,
    including the R- and A-series.
    Each privileged mode has its own copy of some registers;
    the Security and Virtualization extensions add more modes
    (see :class:`ARMPlatformMixinSecurity`
    and :class:`ARMPlatformMixinVirtualization`).

    The A- series supports full application-style multi-tasking.
    The R- series uses the same privilege model as the A- series,
    but it's designed for real-time operations.
    """

    ghidra_register_aliases = _flag_aliases("cpsr")
    status_register: typing.Optional[str] = "cpsr"

    def __init__(self):
        super().__init__()
        self._registers |= {
            # *** Special Registers ***
            # Current Program Status Register
            # NOTE: CPSR has a few masked views
            # which I'm not including:
            # - apsr: Just the condition flags
            # - isetstate: Just includes instruction set control bits
            # - itstate: Just includes state bits for Thumb IT instruction
            "cpsr": RegisterDef(name="cpsr", size=4),
            # Saved Program Status Register
            "spsr": RegisterDef(name="spsr", size=4),
            # *** Register Banks ***
            # sp, lr, and spsr are actually aliases to one of these.
            # Which one they reference depends on execution mode.
            # Emulators that care should be careful when loading state.
            # NOTE: Use User-mode copies of registers unless the mode has its own.
            # NOTE: The user-mode bank is only used if you're in a different privilege mode.
            # User-mode Stack Pointer
            "sp_usr": RegisterDef(name="sp_usr", size=4),
            # User-mode Link Register
            "lr_usr": RegisterDef(name="lr_usr", size=4),
            # User-mode r8
            "r8_usr": RegisterDef(name="r8_usr", size=4),
            # User-mode r9
            "r9_usr": RegisterDef(name="r9_usr", size=4),
            # User-mode r10
            "r10_usr": RegisterDef(name="r10_usr", size=4),
            # User-mode r11
            "r11_usr": RegisterDef(name="r11_usr", size=4),
            # User-mode r12
            "r12_usr": RegisterDef(name="r12_usr", size=4),
            # Supervisor Stack Pointer
            "sp_svc": RegisterDef(name="sp_svc", size=4),
            # Supervisor Link Register
            "lr_svc": RegisterDef(name="lr_svc", size=4),
            # Supervisor Saved PSR
            "spsr_svc": RegisterDef(name="spsr_svc", size=4),
            # Abort-state Stack Pointer
            "sp_abt": RegisterDef(name="sp_abt", size=4),
            # Abort-state Link Register
            "lr_abt": RegisterDef(name="lr_abt", size=4),
            # Abort-state Saved PSR
            "spsr_abt": RegisterDef(name="spsr_abt", size=4),
            # Undefined-mode Stack Pointer
            "sp_und": RegisterDef(name="sp_und", size=4),
            # Undefined-mode Link Register
            "lr_und": RegisterDef(name="lr_und", size=4),
            # Undefined-mode Saved PSR
            "spsr_und": RegisterDef(name="spsr_und", size=4),
            # IRQ-mode Stack Pointer
            "sp_irq": RegisterDef(name="sp_irq", size=4),
            # IRQ-mode Link Register
            "lr_irq": RegisterDef(name="lr_irq", size=4),
            # IRQ-mode Saved PSR
            "spsr_irq": RegisterDef(name="spsr_irq", size=4),
            # FIQ-mode Stack Pointer
            "sp_fiq": RegisterDef(name="sp_fiq", size=4),
            # FIQ-mode Link Register
            "lr_fiq": RegisterDef(name="lr_fiq", size=4),
            # FIQ-mode Saved PSR
            "spsr_fiq": RegisterDef(name="spsr_fiq", size=4),
            # FIQ-mode r8
            "r8_fiq": RegisterDef(name="r8_fiq", size=4),
            # FIQ-mode r9
            "r9_fiq": RegisterDef(name="r9_fiq", size=4),
            # FIQ-mode r10
            "r10_fiq": RegisterDef(name="r10_fiq", size=4),
            # FIQ-mode r11
            "r11_fiq": RegisterDef(name="r11_fiq", size=4),
            # FIQ-mode r12
            "r12_fiq": RegisterDef(name="r12_fiq", size=4),
        }


class ARMPlatformMixinSecurity:
    """Mixin for CPUs with the Security Extensions (TrustZone).

    These add Monitor mode, with its own register bank,
    and the cp15 registers that control the security state.
    They're optional in ARMv6K/ARMv7-A, and absent from ARMv7-R.

    NOTE: Several cp15 registers have separate Secure and Non-secure copies;
    only the copy for the current security state is modeled.
    """

    def __init__(self):
        super().__init__()
        self._registers |= {
            # Monitor-mode Stack Pointer
            "sp_mon": RegisterDef(name="sp_mon", size=4),
            # Monitor-mode Link Register
            "lr_mon": RegisterDef(name="lr_mon", size=4),
            # Monitor-mode Saved PSR
            "spsr_mon": RegisterDef(name="spsr_mon", size=4),
            # Secure Configuration Register
            "scr": RegisterDef(name="scr", size=4),
            # Secure Debug Enable Register
            "sder": RegisterDef(name="sder", size=4),
            # Non-Secure Access Control Register
            "nsacr": RegisterDef(name="nsacr", size=4),
            # Monitor Vector Base Address Register
            "mvbar": RegisterDef(name="mvbar", size=4),
        }


class ARMPlatformMixinVirtualization:
    """Mixin for CPUs with the Virtualization Extensions.

    These add Hypervisor mode, with its own register bank,
    and the cp15 registers that control it.
    They're optional in ARMv7-A, and absent from ARMv7-R.

    NOTE: The hyp-mode timer registers assume the Generic Timer is present.
    """

    def __init__(self):
        super().__init__()
        self._registers |= {
            # Hypervisor Stack Pointer
            "sp_hyp": RegisterDef(name="sp_hyp", size=4),
            # Hypervisor Saved PSR
            "spsr_hyp": RegisterDef(name="spsr_hyp", size=4),
            # Hypervisor Exception Link Register
            # NOTE: Hyp mode has no banked lr; it uses lr_usr.
            "elr_hyp": RegisterDef(name="elr_hyp", size=4),
            # Hyp Configuration Register
            "hcr": RegisterDef(name="hcr", size=4),
            # Hyp Coprocessor Trap Register
            "hcptr": RegisterDef(name="hcptr", size=4),
            # Hyp System Trap Register
            "hstr": RegisterDef(name="hstr", size=4),
            # Hyp Debug Configuration Register
            "hdcr": RegisterDef(name="hdcr", size=4),
            # Hyp System Control Register
            "hsctlr": RegisterDef(name="hsctlr", size=4),
            # Hyp Vector Base Address Register
            "hvbar": RegisterDef(name="hvbar", size=4),
            # Hyp Translation Table Base Register
            "httbr": RegisterDef(name="httbr", size=8),
            # Hyp Translation Control Register
            "htcr": RegisterDef(name="htcr", size=4),
            # Virtualization Translation Table Base Register
            "vttbr": RegisterDef(name="vttbr", size=8),
            # Virtualization Translation Control Register
            "vtcr": RegisterDef(name="vtcr", size=4),
            # Hyp Syndrome Register
            "hsr": RegisterDef(name="hsr", size=4),
            # Hyp Data Fault Address Register
            "hdfar": RegisterDef(name="hdfar", size=4),
            # Hyp Instruction Fault Address Register
            "hifar": RegisterDef(name="hifar", size=4),
            # Hyp IPA Fault Address Register
            "hpfar": RegisterDef(name="hpfar", size=4),
            # Hyp Software Thread ID Register
            "htpidr": RegisterDef(name="htpidr", size=4),
            # Hyp Memory Attribute Indirection Register 0
            "hmair0": RegisterDef(name="hmair0", size=4),
            # Hyp Memory Attribute Indirection Register 1
            "hmair1": RegisterDef(name="hmair1", size=4),
            # Virtualization Processor ID Register
            "vpidr": RegisterDef(name="vpidr", size=4),
            # Virtualization Multiprocessor ID Register
            "vmpidr": RegisterDef(name="vmpidr", size=4),
            # Virtual Offset Register
            "cntvoff": RegisterDef(name="cntvoff", size=8),
            # Timer PL2 Control Register
            "cnthctl": RegisterDef(name="cnthctl", size=4),
            # PL2 Physical Timer Control Register
            "cnthp_ctl": RegisterDef(name="cnthp_ctl", size=4),
            # PL2 Physical Timer CompareValue Register
            "cnthp_cval": RegisterDef(name="cnthp_cval", size=8),
        }


class ARMPlatformMixinV5SystemControl:
    """Mixin for ARMv5 CPUs with a cp15 system control coprocessor

    This is the ARMv5 VMSA register set, as found on an ARM926.
    """

    def __init__(self):
        super().__init__()
        self._registers |= {
            # Main ID Register
            "midr": RegisterDef(name="midr", size=4),
            # Cache Type Register
            "ctr": RegisterDef(name="ctr", size=4),
            # System Control Register
            "sctlr": RegisterDef(name="sctlr", size=4),
            # Translation Table Base Register
            "ttbr": RegisterDef(name="ttbr", size=4),
            # Domain Access Control Register
            "dacr": RegisterDef(name="dacr", size=4),
            # Fault Status Register
            "fsr": RegisterDef(name="fsr", size=4),
            # Fault Address Register
            "far": RegisterDef(name="far", size=4),
            # FCSE Process ID Register
            "fcseidr": RegisterDef(name="fcseidr", size=4),
        }


class ARMPlatformMixinV7SystemControl:
    """Mixin for the cp15 registers common to ARMv7-A and ARMv7-R"""

    def __init__(self):
        super().__init__()
        self._registers |= {
            # Main ID Register
            "midr": RegisterDef(name="midr", size=4),
            # Cache Type Register
            "ctr": RegisterDef(name="ctr", size=4),
            # Multiprocessor Affinity Register
            "mpidr": RegisterDef(name="mpidr", size=4),
            # System Control Register
            "sctlr": RegisterDef(name="sctlr", size=4),
            # Auxiliary Control Register
            "actlr": RegisterDef(name="actlr", size=4),
            # Coprocessor Access Control Register
            "cpacr": RegisterDef(name="cpacr", size=4),
            # Cache Size Selection Register
            "csselr": RegisterDef(name="csselr", size=4),
            # Data Fault Status Register
            "dfsr": RegisterDef(name="dfsr", size=4),
            # Instruction Fault Status Register
            "ifsr": RegisterDef(name="ifsr", size=4),
            # Data Fault Address Register
            "dfar": RegisterDef(name="dfar", size=4),
            # Instruction Fault Address Register
            "ifar": RegisterDef(name="ifar", size=4),
            # Context ID Register
            "contextidr": RegisterDef(name="contextidr", size=4),
            # User Read/Write Thread ID Register
            "tpidrurw": RegisterDef(name="tpidrurw", size=4),
            # User Read-Only Thread ID Register
            "tpidruro": RegisterDef(name="tpidruro", size=4),
            # PL1-only Thread ID Register
            "tpidrprw": RegisterDef(name="tpidrprw", size=4),
        }


class ARMPlatformMixinPMSA:
    """Mixin for ARMv7 CPUs with an MPU (the R-series)

    drbar, drsr, and dracr access whichever region rgnr selects;
    the per-region registers behind them aren't modeled.
    """

    def __init__(self):
        super().__init__()
        self._registers |= {
            # MPU Region Number Register
            "rgnr": RegisterDef(name="rgnr", size=4),
            # Data Region Base Address Register
            "drbar": RegisterDef(name="drbar", size=4),
            # Data Region Size and Enable Register
            "drsr": RegisterDef(name="drsr", size=4),
            # Data Region Access Control Register
            "dracr": RegisterDef(name="dracr", size=4),
        }


class ARMPlatformMixinVMSA:
    """Mixin for ARMv7 CPUs with an MMU and the Large Physical Address Extension

    LPAE widens ttbr0, ttbr1, and par to 64 bits;
    with long descriptors, prrr and nmrr act as MAIR0 and MAIR1.
    """

    def __init__(self):
        super().__init__()
        self._registers |= {
            # Translation Table Base Register 0
            "ttbr0": RegisterDef(name="ttbr0", size=8),
            # Translation Table Base Register 1
            "ttbr1": RegisterDef(name="ttbr1", size=8),
            # Translation Table Base Control Register
            "ttbcr": RegisterDef(name="ttbcr", size=4),
            # Domain Access Control Register
            "dacr": RegisterDef(name="dacr", size=4),
            # Physical Address Register
            "par": RegisterDef(name="par", size=8),
            # Primary Region Remap Register
            "prrr": RegisterDef(name="prrr", size=4),
            # Normal Memory Remap Register
            "nmrr": RegisterDef(name="nmrr", size=4),
            # Vector Base Address Register
            "vbar": RegisterDef(name="vbar", size=4),
        }


class ARMPlatformMixinGenericTimer:
    """Mixin for ARMv7 CPUs with the Generic Timer Extension

    The TVAL registers are views of CVAL minus the count,
    not separate state, so they aren't included.
    """

    def __init__(self):
        super().__init__()
        self._registers |= {
            # Counter Frequency Register
            "cntfrq": RegisterDef(name="cntfrq", size=4),
            # Timer PL1 Control Register
            "cntkctl": RegisterDef(name="cntkctl", size=4),
            # Physical Count Register
            "cntpct": RegisterDef(name="cntpct", size=8),
            # Virtual Count Register
            "cntvct": RegisterDef(name="cntvct", size=8),
            # PL1 Physical Timer Control Register
            "cntp_ctl": RegisterDef(name="cntp_ctl", size=4),
            # PL1 Physical Timer CompareValue Register
            "cntp_cval": RegisterDef(name="cntp_cval", size=8),
            # Virtual Timer Control Register
            "cntv_ctl": RegisterDef(name="cntv_ctl", size=4),
            # Virtual Timer CompareValue Register
            "cntv_cval": RegisterDef(name="cntv_cval", size=8),
        }


class ARMPlatformMixinFPEL:
    """Mixin for little-endian ARM CPUs with a 16-register VFP

    This covers VFPv3-D16 and VFPv4-D16, as found on the R-series,
    which offer 64-bit scalar operations on d0-d15,
    and no Advanced SIMD (NEON).
    """

    def __init__(self):
        super().__init__()
        self._registers |= {
            # *** Floating point control registers ***
            # Floating-point Status and Control Register
            "fpscr": RegisterDef(name="fpscr", size=4),
            # Floating-point Exception Control Register
            "fpexc": RegisterDef(name="fpexc", size=4),
            # Floating-point System ID Register
            "fpsid": RegisterDef(name="fpsid", size=4),
            # Media and VFP Feature Register 0
            "mvfr0": RegisterDef(name="mvfr0", size=4),
            # Media and VFP Feature Register 1
            "mvfr1": RegisterDef(name="mvfr1", size=4),
            # *** Floating point registers ***
            "d0": RegisterDef(name="d0", size=8),
            "s0": RegisterAliasDef(name="s0", parent="d0", size=4, offset=0),
            "s1": RegisterAliasDef(name="s1", parent="d0", size=4, offset=4),
            "d1": RegisterDef(name="d1", size=8),
            "s2": RegisterAliasDef(name="s2", parent="d1", size=4, offset=0),
            "s3": RegisterAliasDef(name="s3", parent="d1", size=4, offset=4),
            "d2": RegisterDef(name="d2", size=8),
            "s4": RegisterAliasDef(name="s4", parent="d2", size=4, offset=0),
            "s5": RegisterAliasDef(name="s5", parent="d2", size=4, offset=4),
            "d3": RegisterDef(name="d3", size=8),
            "s6": RegisterAliasDef(name="s6", parent="d3", size=4, offset=0),
            "s7": RegisterAliasDef(name="s7", parent="d3", size=4, offset=4),
            "d4": RegisterDef(name="d4", size=8),
            "s8": RegisterAliasDef(name="s8", parent="d4", size=4, offset=0),
            "s9": RegisterAliasDef(name="s9", parent="d4", size=4, offset=4),
            "d5": RegisterDef(name="d5", size=8),
            "s10": RegisterAliasDef(name="s10", parent="d5", size=4, offset=0),
            "s11": RegisterAliasDef(name="s11", parent="d5", size=4, offset=4),
            "d6": RegisterDef(name="d6", size=8),
            "s12": RegisterAliasDef(name="s12", parent="d6", size=4, offset=0),
            "s13": RegisterAliasDef(name="s13", parent="d6", size=4, offset=4),
            "d7": RegisterDef(name="d7", size=8),
            "s14": RegisterAliasDef(name="s14", parent="d7", size=4, offset=0),
            "s15": RegisterAliasDef(name="s15", parent="d7", size=4, offset=4),
            "d8": RegisterDef(name="d8", size=8),
            "s16": RegisterAliasDef(name="s16", parent="d8", size=4, offset=0),
            "s17": RegisterAliasDef(name="s17", parent="d8", size=4, offset=4),
            "d9": RegisterDef(name="d9", size=8),
            "s18": RegisterAliasDef(name="s18", parent="d9", size=4, offset=0),
            "s19": RegisterAliasDef(name="s19", parent="d9", size=4, offset=4),
            "d10": RegisterDef(name="d10", size=8),
            "s20": RegisterAliasDef(name="s20", parent="d10", size=4, offset=0),
            "s21": RegisterAliasDef(name="s21", parent="d10", size=4, offset=4),
            "d11": RegisterDef(name="d11", size=8),
            "s22": RegisterAliasDef(name="s22", parent="d11", size=4, offset=0),
            "s23": RegisterAliasDef(name="s23", parent="d11", size=4, offset=4),
            "d12": RegisterDef(name="d12", size=8),
            "s24": RegisterAliasDef(name="s24", parent="d12", size=4, offset=0),
            "s25": RegisterAliasDef(name="s25", parent="d12", size=4, offset=4),
            "d13": RegisterDef(name="d13", size=8),
            "s26": RegisterAliasDef(name="s26", parent="d13", size=4, offset=0),
            "s27": RegisterAliasDef(name="s27", parent="d13", size=4, offset=4),
            "d14": RegisterDef(name="d14", size=8),
            "s28": RegisterAliasDef(name="s28", parent="d14", size=4, offset=0),
            "s29": RegisterAliasDef(name="s29", parent="d14", size=4, offset=4),
            "d15": RegisterDef(name="d15", size=8),
            "s30": RegisterAliasDef(name="s30", parent="d15", size=4, offset=0),
            "s31": RegisterAliasDef(name="s31", parent="d15", size=4, offset=4),
        }


class ARMPlatformMixinVFPEL:
    """Mixin for little-endian ARM CPUs with 32-register VFP and NEON

    This covers VFPv3-D32 or VFPv4-D32 with Advanced SIMD (NEON),
    which supports up to 128-bit scalar and SIMD vector operations.

    VFP and NEON are both optional; NEON requires VFP,
    but VFP can exist alone with 16 or 32 double registers.
    This is the maximal set of registers, assuming both are supported.
    """

    def __init__(self):
        super().__init__()
        # TODO: Add the floating-point conditionals
        self._registers |= {
            # *** Floating-point Control Registers ***
            # Floating-point Status and Control Register
            "fpscr": RegisterDef(name="fpscr", size=4),
            # Floating-point Exception Control Register
            "fpexc": RegisterDef(name="fpexc", size=4),
            # Floating-point System ID Register
            "fpsid": RegisterDef(name="fpsid", size=4),
            # Media and VFP Feature Register 0
            "mvfr0": RegisterDef(name="mvfr0", size=4),
            # Media and VFP Feature Register 1
            "mvfr1": RegisterDef(name="mvfr1", size=4),
            # *** Floating-point Registers ****
            "q0": RegisterDef(name="q0", size=16),
            "d0": RegisterAliasDef(name="d0", parent="q0", size=8, offset=0),
            "s0": RegisterAliasDef(name="s0", parent="q0", size=4, offset=0),
            "s1": RegisterAliasDef(name="s1", parent="q0", size=4, offset=4),
            "d1": RegisterAliasDef(name="d1", parent="q0", size=8, offset=8),
            "s2": RegisterAliasDef(name="s2", parent="q0", size=4, offset=8),
            "s3": RegisterAliasDef(name="s3", parent="q0", size=4, offset=12),
            "q1": RegisterDef(name="q1", size=16),
            "d2": RegisterAliasDef(name="d2", parent="q1", size=8, offset=0),
            "s4": RegisterAliasDef(name="s4", parent="q1", size=4, offset=0),
            "s5": RegisterAliasDef(name="s5", parent="q1", size=4, offset=4),
            "d3": RegisterAliasDef(name="d3", parent="q1", size=8, offset=8),
            "s6": RegisterAliasDef(name="s6", parent="q1", size=4, offset=8),
            "s7": RegisterAliasDef(name="s7", parent="q1", size=4, offset=12),
            "q2": RegisterDef(name="q2", size=16),
            "d4": RegisterAliasDef(name="d4", parent="q2", size=8, offset=0),
            "s8": RegisterAliasDef(name="s8", parent="q2", size=4, offset=0),
            "s9": RegisterAliasDef(name="s9", parent="q2", size=4, offset=4),
            "d5": RegisterAliasDef(name="d5", parent="q2", size=8, offset=8),
            "s10": RegisterAliasDef(name="s10", parent="q2", size=4, offset=8),
            "s11": RegisterAliasDef(name="s11", parent="q2", size=4, offset=12),
            "q3": RegisterDef(name="q3", size=16),
            "d6": RegisterAliasDef(name="d6", parent="q3", size=8, offset=0),
            "s12": RegisterAliasDef(name="s12", parent="q3", size=4, offset=0),
            "s13": RegisterAliasDef(name="s13", parent="q3", size=4, offset=4),
            "d7": RegisterAliasDef(name="d7", parent="q3", size=8, offset=8),
            "s14": RegisterAliasDef(name="s14", parent="q3", size=4, offset=8),
            "s15": RegisterAliasDef(name="s15", parent="q3", size=4, offset=12),
            "q4": RegisterDef(name="q4", size=16),
            "d8": RegisterAliasDef(name="d8", parent="q4", size=8, offset=0),
            "s16": RegisterAliasDef(name="s16", parent="q4", size=4, offset=0),
            "s17": RegisterAliasDef(name="s17", parent="q4", size=4, offset=4),
            "d9": RegisterAliasDef(name="d9", parent="q4", size=8, offset=8),
            "s18": RegisterAliasDef(name="s18", parent="q4", size=4, offset=8),
            "s19": RegisterAliasDef(name="s19", parent="q4", size=4, offset=12),
            "q5": RegisterDef(name="q5", size=16),
            "d10": RegisterAliasDef(name="d10", parent="q5", size=8, offset=0),
            "s20": RegisterAliasDef(name="s20", parent="q5", size=4, offset=0),
            "s21": RegisterAliasDef(name="s21", parent="q5", size=4, offset=4),
            "d11": RegisterAliasDef(name="d11", parent="q5", size=8, offset=8),
            "s22": RegisterAliasDef(name="s22", parent="q5", size=4, offset=8),
            "s23": RegisterAliasDef(name="s23", parent="q5", size=4, offset=12),
            "q6": RegisterDef(name="q6", size=16),
            "d12": RegisterAliasDef(name="d12", parent="q6", size=8, offset=0),
            "s24": RegisterAliasDef(name="s24", parent="q6", size=4, offset=0),
            "s25": RegisterAliasDef(name="s25", parent="q6", size=4, offset=4),
            "d13": RegisterAliasDef(name="d13", parent="q6", size=8, offset=8),
            "s26": RegisterAliasDef(name="s26", parent="q6", size=4, offset=8),
            "s27": RegisterAliasDef(name="s27", parent="q6", size=4, offset=12),
            "q7": RegisterDef(name="q7", size=16),
            "d14": RegisterAliasDef(name="d14", parent="q7", size=8, offset=0),
            "s28": RegisterAliasDef(name="s28", parent="q7", size=4, offset=0),
            "s29": RegisterAliasDef(name="s29", parent="q7", size=4, offset=4),
            "d15": RegisterAliasDef(name="d15", parent="q7", size=8, offset=8),
            "s30": RegisterAliasDef(name="s30", parent="q7", size=4, offset=8),
            "s31": RegisterAliasDef(name="s31", parent="q7", size=4, offset=12),
            # NOTE: This isn't a typo; there are only 32 single-precision sX registers
            # This does mean that only half the VFP register space can be used
            # for single-precision arithmetic.
            "q8": RegisterDef(name="q8", size=16),
            "d16": RegisterAliasDef(name="d16", parent="q8", size=8, offset=0),
            "d17": RegisterAliasDef(name="d17", parent="q8", size=8, offset=8),
            "q9": RegisterDef(name="q9", size=16),
            "d18": RegisterAliasDef(name="d18", parent="q9", size=8, offset=0),
            "d19": RegisterAliasDef(name="d19", parent="q9", size=8, offset=8),
            "q10": RegisterDef(name="q10", size=16),
            "d20": RegisterAliasDef(name="d20", parent="q10", size=8, offset=0),
            "d21": RegisterAliasDef(name="d21", parent="q10", size=8, offset=8),
            "q11": RegisterDef(name="q11", size=16),
            "d22": RegisterAliasDef(name="d22", parent="q11", size=8, offset=0),
            "d23": RegisterAliasDef(name="d23", parent="q11", size=8, offset=8),
            "q12": RegisterDef(name="q12", size=16),
            "d24": RegisterAliasDef(name="d24", parent="q12", size=8, offset=0),
            "d25": RegisterAliasDef(name="d25", parent="q12", size=8, offset=8),
            "q13": RegisterDef(name="q13", size=16),
            "d26": RegisterAliasDef(name="d26", parent="q13", size=8, offset=0),
            "d27": RegisterAliasDef(name="d27", parent="q13", size=8, offset=8),
            "q14": RegisterDef(name="q14", size=16),
            "d28": RegisterAliasDef(name="d28", parent="q14", size=8, offset=0),
            "d29": RegisterAliasDef(name="d29", parent="q14", size=8, offset=8),
            "q15": RegisterDef(name="q15", size=16),
            "d30": RegisterAliasDef(name="d30", parent="q15", size=8, offset=0),
            "d31": RegisterAliasDef(name="d31", parent="q15", size=8, offset=8),
        }


class ARMv5T(ARMPlatformMixinV5SystemControl, ARMPlatformMixinBanked, ARMPlatformDef):
    """Platform definition for ARMv5t little-endian.

    VFPv2 is an optional extension on ARMv5; it isn't modeled.
    """

    architecture = Architecture.ARM_V5T
    ghidra_language_id = "ARM:LE:32:v5t"


class ARMv6M(ARMPlatformMixinM, ARMPlatformDef):
    """Platform definition for ARMv6m little-endian.

    ARMv6-M has no floating-point extension.
    """

    architecture = Architecture.ARM_V6M
    ghidra_language_id = "ARM:LE:32:v6"


class ARMv6MThumb(ARMv6M):
    """Platform definition for ARMv6m little-endian in thumb mode.

    Thumb is annoying; most emulators have a very hard time
    switching between arm and thumb instructions,
    despite it being a key feature of many CPUs.
    """

    architecture = Architecture.ARM_V6M_THUMB
    # Thumb-mode platform: override the ARM-mode Capstone default so a
    # disassembler built statically from capstone_mode decodes Thumb.
    capstone_mode = capstone.CS_MODE_THUMB
    # ARMv6-M is Thumb; Ghidra decodes Thumb via the TMode context register
    # within the same SLEIGH language, so this shares ARMv6M's language id.
    ghidra_language_id = "ARM:LE:32:v6"


class ARMv7M(ARMPlatformMixinMMainline, ARMPlatformDef):
    """Platform definition for ARMv7m little-endian

    The FPv4/FPv5 floating-point extensions of ARMv7E-M aren't modeled.
    """

    architecture = Architecture.ARM_V7M
    ghidra_language_id = "ARM:LE:32:v7"


class ARMv7R(
    ARMPlatformMixinFPEL,
    ARMPlatformMixinPMSA,
    ARMPlatformMixinV7SystemControl,
    ARMPlatformMixinBanked,
    ARMPlatformDef,
):
    """Platform definition for ARMv7r little-endian

    ARMv7-R has neither the Security nor the Virtualization Extensions,
    and doesn't support Advanced SIMD.
    """

    architecture = Architecture.ARM_V7R
    # v7R is instruction-compatible with v7A; without this the p-code use/def
    # analysis is skipped (ghidra_language_id inherits None from PlatformDef).
    ghidra_language_id = "ARM:LE:32:v7"


class ARMv7A(
    ARMPlatformMixinVFPEL,
    ARMPlatformMixinVirtualization,
    ARMPlatformMixinSecurity,
    ARMPlatformMixinGenericTimer,
    ARMPlatformMixinVMSA,
    ARMPlatformMixinV7SystemControl,
    ARMPlatformMixinBanked,
    ARMPlatformDef,
):
    """Platform definition for ARMv7a little-endian

    This assumes the optional Security, Virtualization,
    and Generic Timer Extensions, as well as NEON.
    """

    architecture = Architecture.ARM_V7A
    ghidra_language_id = "ARM:LE:32:v7"
