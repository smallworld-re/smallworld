import unicorn

from ....platforms import Architecture, Byteorder
from .machdef import UnicornMachineDef


class ARMMachineDef(UnicornMachineDef):
    """Base Unicorn machine definition for 32-bit ARM"""

    uc_arch = unicorn.UC_ARCH_ARM
    uc_mode = unicorn.UC_MODE_ARM

    def __init__(self):
        self._registers = {
            "r0": unicorn.arm_const.UC_ARM_REG_R0,
            "r1": unicorn.arm_const.UC_ARM_REG_R1,
            "r2": unicorn.arm_const.UC_ARM_REG_R2,
            "r3": unicorn.arm_const.UC_ARM_REG_R3,
            "r4": unicorn.arm_const.UC_ARM_REG_R4,
            "r5": unicorn.arm_const.UC_ARM_REG_R5,
            "r6": unicorn.arm_const.UC_ARM_REG_R6,
            "r7": unicorn.arm_const.UC_ARM_REG_R7,
            "r8": unicorn.arm_const.UC_ARM_REG_R8,
            # r9 doubles as the Static base pointer
            "r9": unicorn.arm_const.UC_ARM_REG_R9,
            "sb": unicorn.arm_const.UC_ARM_REG_SB,
            # r10 doubles as the Stack Limit pointer
            "r10": unicorn.arm_const.UC_ARM_REG_R10,
            "sl": unicorn.arm_const.UC_ARM_REG_SL,
            # r11 doubles as the Frame Pointer, if desired.
            "r11": unicorn.arm_const.UC_ARM_REG_R11,
            "fp": unicorn.arm_const.UC_ARM_REG_FP,
            # r12 doubles as the Intra-call scratch register
            "r12": unicorn.arm_const.UC_ARM_REG_R12,
            "ip": unicorn.arm_const.UC_ARM_REG_IP,
            "sp": unicorn.arm_const.UC_ARM_REG_SP,
            "r13": unicorn.arm_const.UC_ARM_REG_R13,
            "lr": unicorn.arm_const.UC_ARM_REG_LR,
            "r14": unicorn.arm_const.UC_ARM_REG_R14,
            "pc": unicorn.arm_const.UC_ARM_REG_PC,
            "r15": unicorn.arm_const.UC_ARM_REG_R15,
        }


# QEMU's ARM prefetch (instruction) abort exception index (target/arm cpu.h
# EXCP_PREFETCH_ABORT).
_ARM_EXCP_PREFETCH_ABORT = 3


class ARMMachineMixinM:
    """Mixin for ARM M-series machine models"""

    def handle_interrupt(self, intno: int, pc: int) -> None:
        if intno == _ARM_EXCP_PREFETCH_ABORT:
            # A Cortex-M3 reports an instruction fetch from unmapped memory as
            # a prefetch abort rather than as a fetch error.
            raise unicorn.UcError(unicorn.UC_ERR_FETCH_UNMAPPED)
        # The machine def this mixes into provides the default.
        super().handle_interrupt(intno, pc)  # type: ignore[misc]

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # NOTE: PSR is aliased to CPSR
                # This is an artifact of the fact that Unicorn
                # seems to emulate a mash-up of M- and A-series arm.
                "psr": unicorn.arm_const.UC_ARM_REG_CPSR,
                "primask": unicorn.arm_const.UC_ARM_REG_PRIMASK,
                "control": unicorn.arm_const.UC_ARM_REG_CONTROL,
                "msp": unicorn.arm_const.UC_ARM_REG_MSP,
                "psp": unicorn.arm_const.UC_ARM_REG_PSP,
            }
        )


class ARMMachineMixinMMainline(ARMMachineMixinM):
    """Mixin for ARMv7-M CPUs, which add priority masks to ARMv6-M"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                "basepri": unicorn.arm_const.UC_ARM_REG_BASEPRI,
                "faultmask": unicorn.arm_const.UC_ARM_REG_FAULTMASK,
            }
        )


class ARMMachineMixinBanked:
    """Mixin for ARM machine models with the classic banked-register model (non-M-profile)"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                "cpsr": unicorn.arm_const.UC_ARM_REG_CPSR,
                "spsr": unicorn.arm_const.UC_ARM_REG_SPSR,
                # NOTE: None of the banked registers have Unicorn IDs
                "sp_usr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "lr_usr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "r8_usr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "r9_usr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "r10_usr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "r11_usr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "r12_usr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "sp_svc": unicorn.arm_const.UC_ARM_REG_INVALID,
                "lr_svc": unicorn.arm_const.UC_ARM_REG_INVALID,
                "spsr_svc": unicorn.arm_const.UC_ARM_REG_INVALID,
                "sp_abt": unicorn.arm_const.UC_ARM_REG_INVALID,
                "lr_abt": unicorn.arm_const.UC_ARM_REG_INVALID,
                "spsr_abt": unicorn.arm_const.UC_ARM_REG_INVALID,
                "sp_und": unicorn.arm_const.UC_ARM_REG_INVALID,
                "lr_und": unicorn.arm_const.UC_ARM_REG_INVALID,
                "spsr_und": unicorn.arm_const.UC_ARM_REG_INVALID,
                "sp_irq": unicorn.arm_const.UC_ARM_REG_INVALID,
                "lr_irq": unicorn.arm_const.UC_ARM_REG_INVALID,
                "spsr_irq": unicorn.arm_const.UC_ARM_REG_INVALID,
                "sp_fiq": unicorn.arm_const.UC_ARM_REG_INVALID,
                "lr_fiq": unicorn.arm_const.UC_ARM_REG_INVALID,
                "spsr_fiq": unicorn.arm_const.UC_ARM_REG_INVALID,
                "r8_fiq": unicorn.arm_const.UC_ARM_REG_INVALID,
                "r9_fiq": unicorn.arm_const.UC_ARM_REG_INVALID,
                "r10_fiq": unicorn.arm_const.UC_ARM_REG_INVALID,
                "r11_fiq": unicorn.arm_const.UC_ARM_REG_INVALID,
                "r12_fiq": unicorn.arm_const.UC_ARM_REG_INVALID,
            }
        )


class ARMMachineMixinSecurity:
    """Mixin for CPUs with the Security Extensions (TrustZone)."""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                "sp_mon": unicorn.arm_const.UC_ARM_REG_INVALID,
                "lr_mon": unicorn.arm_const.UC_ARM_REG_INVALID,
                "spsr_mon": unicorn.arm_const.UC_ARM_REG_INVALID,
                "scr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "sder": unicorn.arm_const.UC_ARM_REG_INVALID,
                "nsacr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "mvbar": unicorn.arm_const.UC_ARM_REG_INVALID,
            }
        )


class ARMMachineMixinVirtualization:
    """Mixin for CPUs with the Virtualization Extensions."""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                "sp_hyp": unicorn.arm_const.UC_ARM_REG_INVALID,
                "spsr_hyp": unicorn.arm_const.UC_ARM_REG_INVALID,
                "elr_hyp": unicorn.arm_const.UC_ARM_REG_INVALID,
                "hcr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "hcptr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "hstr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "hdcr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "hsctlr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "hvbar": unicorn.arm_const.UC_ARM_REG_INVALID,
                "httbr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "htcr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "vttbr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "vtcr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "hsr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "hdfar": unicorn.arm_const.UC_ARM_REG_INVALID,
                "hifar": unicorn.arm_const.UC_ARM_REG_INVALID,
                "hpfar": unicorn.arm_const.UC_ARM_REG_INVALID,
                "htpidr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "hmair0": unicorn.arm_const.UC_ARM_REG_INVALID,
                "hmair1": unicorn.arm_const.UC_ARM_REG_INVALID,
                "vpidr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "vmpidr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "cntvoff": unicorn.arm_const.UC_ARM_REG_INVALID,
                "cnthctl": unicorn.arm_const.UC_ARM_REG_INVALID,
                "cnthp_ctl": unicorn.arm_const.UC_ARM_REG_INVALID,
                "cnthp_cval": unicorn.arm_const.UC_ARM_REG_INVALID,
            }
        )


class ARMMachineMixinV5SystemControl:
    """Mixin for ARMv5 CPUs with a cp15 system control coprocessor"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                "midr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "ctr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "sctlr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "ttbr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "dacr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "fsr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "far": unicorn.arm_const.UC_ARM_REG_INVALID,
                "fcseidr": unicorn.arm_const.UC_ARM_REG_INVALID,
            }
        )


class ARMMachineMixinV6SystemControl:
    """Mixin for ARMv6 CPUs with a cp15 system control coprocessor"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                "midr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "ctr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "sctlr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "actlr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "cpacr": unicorn.arm_const.UC_ARM_REG_C1_C0_2,
                "ttbr0": unicorn.arm_const.UC_ARM_REG_INVALID,
                "ttbr1": unicorn.arm_const.UC_ARM_REG_INVALID,
                "ttbcr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "dacr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "dfsr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "ifsr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "dfar": unicorn.arm_const.UC_ARM_REG_INVALID,
                "wfar": unicorn.arm_const.UC_ARM_REG_INVALID,
                "ifar": unicorn.arm_const.UC_ARM_REG_INVALID,
                "par": unicorn.arm_const.UC_ARM_REG_INVALID,
                "prrr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "nmrr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "vbar": unicorn.arm_const.UC_ARM_REG_INVALID,
                "fcseidr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "contextidr": unicorn.arm_const.UC_ARM_REG_INVALID,
                # NOTE: Unicorn defines a TPIDRURW ID (C13_C0_2), but as of 2.1.4
                # it isn't backed: it reads 0 and ignores writes.
                "tpidrurw": unicorn.arm_const.UC_ARM_REG_INVALID,
                "tpidruro": unicorn.arm_const.UC_ARM_REG_C13_C0_3,
                "tpidrprw": unicorn.arm_const.UC_ARM_REG_INVALID,
            }
        )


class ARMMachineMixinV7SystemControl:
    """Mixin for the cp15 registers common to ARMv7-A and ARMv7-R"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                "midr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "ctr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "mpidr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "sctlr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "actlr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "cpacr": unicorn.arm_const.UC_ARM_REG_C1_C0_2,
                "csselr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "dfsr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "ifsr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "dfar": unicorn.arm_const.UC_ARM_REG_INVALID,
                "ifar": unicorn.arm_const.UC_ARM_REG_INVALID,
                "contextidr": unicorn.arm_const.UC_ARM_REG_INVALID,
                # NOTE: Unicorn defines a TPIDRURW ID (C13_C0_2), but as of 2.1.4
                # it isn't backed: it reads 0 and ignores writes.
                "tpidrurw": unicorn.arm_const.UC_ARM_REG_INVALID,
                "tpidruro": unicorn.arm_const.UC_ARM_REG_C13_C0_3,
                "tpidrprw": unicorn.arm_const.UC_ARM_REG_INVALID,
            }
        )


class ARMMachineMixinPMSA:
    """Mixin for ARMv7 CPUs with an MPU (the R-series)"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                "rgnr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "drbar": unicorn.arm_const.UC_ARM_REG_INVALID,
                "drsr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "dracr": unicorn.arm_const.UC_ARM_REG_INVALID,
            }
        )


class ARMMachineMixinVMSA:
    """Mixin for ARMv7 CPUs with an MMU and the Large Physical Address Extension"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                "ttbr0": unicorn.arm_const.UC_ARM_REG_INVALID,
                "ttbr1": unicorn.arm_const.UC_ARM_REG_INVALID,
                "ttbcr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "dacr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "par": unicorn.arm_const.UC_ARM_REG_INVALID,
                "prrr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "nmrr": unicorn.arm_const.UC_ARM_REG_INVALID,
                "vbar": unicorn.arm_const.UC_ARM_REG_INVALID,
            }
        )


class ARMMachineMixinGenericTimer:
    """Mixin for ARMv7 CPUs with the Generic Timer Extension"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                "cntfrq": unicorn.arm_const.UC_ARM_REG_INVALID,
                "cntkctl": unicorn.arm_const.UC_ARM_REG_INVALID,
                "cntpct": unicorn.arm_const.UC_ARM_REG_INVALID,
                "cntvct": unicorn.arm_const.UC_ARM_REG_INVALID,
                "cntp_ctl": unicorn.arm_const.UC_ARM_REG_INVALID,
                "cntp_cval": unicorn.arm_const.UC_ARM_REG_INVALID,
                "cntv_ctl": unicorn.arm_const.UC_ARM_REG_INVALID,
                "cntv_cval": unicorn.arm_const.UC_ARM_REG_INVALID,
            }
        )


class ARMMachineMixinFP:
    """Mixin for ARM machine models with basic FPUs"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                "fpscr": unicorn.arm_const.UC_ARM_REG_FPSCR,
                "fpexc": unicorn.arm_const.UC_ARM_REG_FPEXC,
                "fpsid": unicorn.arm_const.UC_ARM_REG_FPSID,
                # NOTE: Unicorn defines MVFR0/MVFR1 IDs, but as of 2.1.4
                # they aren't backed: they read 0 and ignore writes.
                "mvfr0": unicorn.arm_const.UC_ARM_REG_INVALID,
                "mvfr1": unicorn.arm_const.UC_ARM_REG_INVALID,
                "d0": unicorn.arm_const.UC_ARM_REG_D0,
                "s0": unicorn.arm_const.UC_ARM_REG_S0,
                "s1": unicorn.arm_const.UC_ARM_REG_S1,
                "d1": unicorn.arm_const.UC_ARM_REG_D1,
                "s2": unicorn.arm_const.UC_ARM_REG_S2,
                "s3": unicorn.arm_const.UC_ARM_REG_S3,
                "d2": unicorn.arm_const.UC_ARM_REG_D2,
                "s4": unicorn.arm_const.UC_ARM_REG_S4,
                "s5": unicorn.arm_const.UC_ARM_REG_S5,
                "d3": unicorn.arm_const.UC_ARM_REG_D3,
                "s6": unicorn.arm_const.UC_ARM_REG_S6,
                "s7": unicorn.arm_const.UC_ARM_REG_S7,
                "d4": unicorn.arm_const.UC_ARM_REG_D4,
                "s8": unicorn.arm_const.UC_ARM_REG_S8,
                "s9": unicorn.arm_const.UC_ARM_REG_S9,
                "d5": unicorn.arm_const.UC_ARM_REG_D5,
                "s10": unicorn.arm_const.UC_ARM_REG_S10,
                "s11": unicorn.arm_const.UC_ARM_REG_S11,
                "d6": unicorn.arm_const.UC_ARM_REG_D6,
                "s12": unicorn.arm_const.UC_ARM_REG_S12,
                "s13": unicorn.arm_const.UC_ARM_REG_S13,
                "d7": unicorn.arm_const.UC_ARM_REG_D7,
                "s14": unicorn.arm_const.UC_ARM_REG_S14,
                "s15": unicorn.arm_const.UC_ARM_REG_S15,
                "d8": unicorn.arm_const.UC_ARM_REG_D8,
                "s16": unicorn.arm_const.UC_ARM_REG_S16,
                "s17": unicorn.arm_const.UC_ARM_REG_S17,
                "d9": unicorn.arm_const.UC_ARM_REG_D9,
                "s18": unicorn.arm_const.UC_ARM_REG_S18,
                "s19": unicorn.arm_const.UC_ARM_REG_S19,
                "d10": unicorn.arm_const.UC_ARM_REG_D10,
                "s20": unicorn.arm_const.UC_ARM_REG_S20,
                "s21": unicorn.arm_const.UC_ARM_REG_S21,
                "d11": unicorn.arm_const.UC_ARM_REG_D11,
                "s22": unicorn.arm_const.UC_ARM_REG_S22,
                "s23": unicorn.arm_const.UC_ARM_REG_S23,
                "d12": unicorn.arm_const.UC_ARM_REG_D12,
                "s24": unicorn.arm_const.UC_ARM_REG_S24,
                "s25": unicorn.arm_const.UC_ARM_REG_S25,
                "d13": unicorn.arm_const.UC_ARM_REG_D13,
                "s26": unicorn.arm_const.UC_ARM_REG_S26,
                "s27": unicorn.arm_const.UC_ARM_REG_S27,
                "d14": unicorn.arm_const.UC_ARM_REG_D14,
                "s28": unicorn.arm_const.UC_ARM_REG_S28,
                "s29": unicorn.arm_const.UC_ARM_REG_S29,
                "d15": unicorn.arm_const.UC_ARM_REG_D15,
                "s30": unicorn.arm_const.UC_ARM_REG_S30,
                "s31": unicorn.arm_const.UC_ARM_REG_S31,
            }
        )


class ARMMachineMixinVFPv2(ARMMachineMixinFP):
    """Mixin for little-endian ARM CPUs with VFPv2"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # NOTE: Unicorn defines FPINST/FPINST2 IDs, but as of 2.1.4
                # they aren't backed: they read 0 and ignore writes.
                "fpinst": unicorn.arm_const.UC_ARM_REG_INVALID,
                "fpinst2": unicorn.arm_const.UC_ARM_REG_INVALID,
            }
        )


class ARMMachineMixinVFP:
    """Mixin for ARM machine models with VFP/NEON support"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                "fpscr": unicorn.arm_const.UC_ARM_REG_FPSCR,
                "fpexc": unicorn.arm_const.UC_ARM_REG_FPEXC,
                "fpsid": unicorn.arm_const.UC_ARM_REG_FPSID,
                # NOTE: Unicorn defines MVFR0/MVFR1 IDs, but as of 2.1.4
                # they aren't backed: they read 0 and ignore writes.
                "mvfr0": unicorn.arm_const.UC_ARM_REG_INVALID,
                "mvfr1": unicorn.arm_const.UC_ARM_REG_INVALID,
                "q0": unicorn.arm_const.UC_ARM_REG_Q0,
                "d0": unicorn.arm_const.UC_ARM_REG_D0,
                "s0": unicorn.arm_const.UC_ARM_REG_S0,
                "s1": unicorn.arm_const.UC_ARM_REG_S1,
                "d1": unicorn.arm_const.UC_ARM_REG_D1,
                "s2": unicorn.arm_const.UC_ARM_REG_S2,
                "s3": unicorn.arm_const.UC_ARM_REG_S3,
                "q1": unicorn.arm_const.UC_ARM_REG_Q1,
                "d2": unicorn.arm_const.UC_ARM_REG_D2,
                "s4": unicorn.arm_const.UC_ARM_REG_S4,
                "s5": unicorn.arm_const.UC_ARM_REG_S5,
                "d3": unicorn.arm_const.UC_ARM_REG_D3,
                "s6": unicorn.arm_const.UC_ARM_REG_S6,
                "s7": unicorn.arm_const.UC_ARM_REG_S7,
                "q2": unicorn.arm_const.UC_ARM_REG_Q2,
                "d4": unicorn.arm_const.UC_ARM_REG_D4,
                "s8": unicorn.arm_const.UC_ARM_REG_S8,
                "s9": unicorn.arm_const.UC_ARM_REG_S9,
                "d5": unicorn.arm_const.UC_ARM_REG_D5,
                "s10": unicorn.arm_const.UC_ARM_REG_S10,
                "s11": unicorn.arm_const.UC_ARM_REG_S11,
                "q3": unicorn.arm_const.UC_ARM_REG_Q3,
                "d6": unicorn.arm_const.UC_ARM_REG_D6,
                "s12": unicorn.arm_const.UC_ARM_REG_S12,
                "s13": unicorn.arm_const.UC_ARM_REG_S13,
                "d7": unicorn.arm_const.UC_ARM_REG_D7,
                "s14": unicorn.arm_const.UC_ARM_REG_S14,
                "s15": unicorn.arm_const.UC_ARM_REG_S15,
                "q4": unicorn.arm_const.UC_ARM_REG_Q4,
                "d8": unicorn.arm_const.UC_ARM_REG_D8,
                "s16": unicorn.arm_const.UC_ARM_REG_S16,
                "s17": unicorn.arm_const.UC_ARM_REG_S17,
                "d9": unicorn.arm_const.UC_ARM_REG_D9,
                "s18": unicorn.arm_const.UC_ARM_REG_S18,
                "s19": unicorn.arm_const.UC_ARM_REG_S19,
                "q5": unicorn.arm_const.UC_ARM_REG_Q5,
                "d10": unicorn.arm_const.UC_ARM_REG_D10,
                "s20": unicorn.arm_const.UC_ARM_REG_S20,
                "s21": unicorn.arm_const.UC_ARM_REG_S21,
                "d11": unicorn.arm_const.UC_ARM_REG_D11,
                "s22": unicorn.arm_const.UC_ARM_REG_S22,
                "s23": unicorn.arm_const.UC_ARM_REG_S23,
                "q6": unicorn.arm_const.UC_ARM_REG_Q6,
                "d12": unicorn.arm_const.UC_ARM_REG_D12,
                "s24": unicorn.arm_const.UC_ARM_REG_S24,
                "s25": unicorn.arm_const.UC_ARM_REG_S25,
                "d13": unicorn.arm_const.UC_ARM_REG_D13,
                "s26": unicorn.arm_const.UC_ARM_REG_S26,
                "s27": unicorn.arm_const.UC_ARM_REG_S27,
                "q7": unicorn.arm_const.UC_ARM_REG_Q7,
                "d14": unicorn.arm_const.UC_ARM_REG_D14,
                "s28": unicorn.arm_const.UC_ARM_REG_S28,
                "s29": unicorn.arm_const.UC_ARM_REG_S29,
                "d15": unicorn.arm_const.UC_ARM_REG_D15,
                "s30": unicorn.arm_const.UC_ARM_REG_S30,
                "s31": unicorn.arm_const.UC_ARM_REG_S31,
                "q8": unicorn.arm_const.UC_ARM_REG_Q8,
                "d16": unicorn.arm_const.UC_ARM_REG_D16,
                "d17": unicorn.arm_const.UC_ARM_REG_D17,
                "q9": unicorn.arm_const.UC_ARM_REG_Q9,
                "d18": unicorn.arm_const.UC_ARM_REG_D18,
                "d19": unicorn.arm_const.UC_ARM_REG_D19,
                "q10": unicorn.arm_const.UC_ARM_REG_Q10,
                "d20": unicorn.arm_const.UC_ARM_REG_D20,
                "d21": unicorn.arm_const.UC_ARM_REG_D21,
                "q11": unicorn.arm_const.UC_ARM_REG_Q11,
                "d22": unicorn.arm_const.UC_ARM_REG_D22,
                "d23": unicorn.arm_const.UC_ARM_REG_D23,
                "q12": unicorn.arm_const.UC_ARM_REG_Q12,
                "d24": unicorn.arm_const.UC_ARM_REG_D24,
                "d25": unicorn.arm_const.UC_ARM_REG_D25,
                "q13": unicorn.arm_const.UC_ARM_REG_Q13,
                "d26": unicorn.arm_const.UC_ARM_REG_D26,
                "d27": unicorn.arm_const.UC_ARM_REG_D27,
                "q14": unicorn.arm_const.UC_ARM_REG_Q14,
                "d28": unicorn.arm_const.UC_ARM_REG_D28,
                "d29": unicorn.arm_const.UC_ARM_REG_D29,
                "q15": unicorn.arm_const.UC_ARM_REG_Q15,
                "d30": unicorn.arm_const.UC_ARM_REG_D30,
                "d31": unicorn.arm_const.UC_ARM_REG_D31,
            }
        )


class ARMv5TMachineDef(
    ARMMachineMixinV5SystemControl, ARMMachineMixinBanked, ARMMachineDef
):
    """Unicorn machine definition for ARMv5T little-endian"""

    arch = Architecture.ARM_V5T
    byteorder = Byteorder.LITTLE


class ARMv6KMachineDef(
    ARMMachineMixinVFPv2,
    ARMMachineMixinSecurity,
    ARMMachineMixinV6SystemControl,
    ARMMachineMixinBanked,
    ARMMachineDef,
):
    """Unicorn machine definition for ARMv6K little-endian"""

    arch = Architecture.ARM_V6K
    byteorder = Byteorder.LITTLE
    uc_cpu = unicorn.arm_const.UC_CPU_ARM_1176


class ARMv6MMachineDef(ARMMachineMixinM, ARMMachineDef):
    """Unicorn machine definition for ARMv6-M little-endian"""

    arch = Architecture.ARM_V6M
    byteorder = Byteorder.LITTLE
    # NOTE: Don't add UC_MODE_MCLASS; as of Unicorn 2.1.4,
    # it overrides uc_cpu and forces a Cortex-M33.
    uc_cpu = unicorn.arm_const.UC_CPU_ARM_CORTEX_M0
    # M-profile is Thumb-only.
    uc_mode = unicorn.UC_MODE_THUMB


class ARMv6MThumbMachineDef(ARMv6MMachineDef):
    """Unicorn machine definition for ARMv6-M little-endian, THUMB ISA"""

    arch = Architecture.ARM_V6M_THUMB
    uc_mode = unicorn.UC_MODE_THUMB


class ARMv7MMachineDef(ARMMachineMixinMMainline, ARMMachineDef):
    """Unicorn machine definition for ARMv7-M little-endian"""

    arch = Architecture.ARM_V7M
    byteorder = Byteorder.LITTLE
    # NOTE: Don't add UC_MODE_MCLASS; as of Unicorn 2.1.4,
    # it overrides uc_cpu and forces a Cortex-M33.
    uc_cpu = unicorn.arm_const.UC_CPU_ARM_CORTEX_M3
    # M-profile is Thumb-only.
    uc_mode = unicorn.UC_MODE_THUMB


class ARMv7RMachineDef(
    ARMMachineMixinFP,
    ARMMachineMixinPMSA,
    ARMMachineMixinV7SystemControl,
    ARMMachineMixinBanked,
    ARMMachineDef,
):
    """Unicorn machine definition for ARMv7-R little-endian"""

    arch = Architecture.ARM_V7R
    byteorder = Byteorder.LITTLE


class ARMv7AMachineDef(
    ARMMachineMixinVFP,
    ARMMachineMixinVirtualization,
    ARMMachineMixinSecurity,
    ARMMachineMixinGenericTimer,
    ARMMachineMixinVMSA,
    ARMMachineMixinV7SystemControl,
    ARMMachineMixinBanked,
    ARMMachineDef,
):
    """Unicorn machine definition for ARMv7-A little-endian"""

    arch = Architecture.ARM_V7A
    byteorder = Byteorder.LITTLE
