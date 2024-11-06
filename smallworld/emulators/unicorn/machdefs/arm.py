import capstone
import unicorn

from ....platforms import Architecture, Byteorder
from .machdef import UnicornMachineDef


class ARMMachineDef(UnicornMachineDef):
    """Base Unicorn machine definition for 32-bit ARM"""

    uc_arch = unicorn.UC_ARCH_ARM
    uc_mode = unicorn.UC_MODE_ARM

    cs_arch = capstone.CS_ARCH_ARM
    cs_mode = capstone.CS_MODE_ARM

    pc_reg = "pc"

    def __init__(self):
        self._registers = {
            "r0": (unicorn.arm_const.UC_ARM_REG_R0, "r0", 0, 4),
            "r1": (unicorn.arm_const.UC_ARM_REG_R1, "r1", 0, 4),
            "r2": (unicorn.arm_const.UC_ARM_REG_R2, "r2", 0, 4),
            "r3": (unicorn.arm_const.UC_ARM_REG_R3, "r3", 0, 4),
            "r4": (unicorn.arm_const.UC_ARM_REG_R4, "r4", 0, 4),
            "r5": (unicorn.arm_const.UC_ARM_REG_R5, "r5", 0, 4),
            "r6": (unicorn.arm_const.UC_ARM_REG_R6, "r6", 0, 4),
            "r7": (unicorn.arm_const.UC_ARM_REG_R7, "r7", 0, 4),
            "r8": (unicorn.arm_const.UC_ARM_REG_R8, "r8", 0, 4),
            # r9 doubles as the Static base pointer
            "r9": (unicorn.arm_const.UC_ARM_REG_R9, "r9", 0, 4),
            "sb": (unicorn.arm_const.UC_ARM_REG_SB, "r9", 0, 4),
            # r10 doubles as the Stack Limit pointer
            "r10": (unicorn.arm_const.UC_ARM_REG_R10, "r10", 0, 4),
            "sl": (unicorn.arm_const.UC_ARM_REG_SL, "r10", 0, 4),
            # r11 doubles as the Frame Pointer, if desired.
            "r11": (unicorn.arm_const.UC_ARM_REG_R11, "r11", 0, 4),
            "fp": (unicorn.arm_const.UC_ARM_REG_FP, "r11", 0, 4),
            # r12 doubles as the Intra-call scratch register
            "r12": (unicorn.arm_const.UC_ARM_REG_R12, "r12", 0, 4),
            "ip": (unicorn.arm_const.UC_ARM_REG_IP, "r12", 0, 4),
            "sp": (unicorn.arm_const.UC_ARM_REG_SP, "sp", 0, 4),
            "lr": (unicorn.arm_const.UC_ARM_REG_LR, "lr", 0, 4),
            "pc": (unicorn.arm_const.UC_ARM_REG_PC, "pc", 0, 4),
        }


class ARMMachineMixinM:
    """Mixin for ARM M-series machine models"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # NOTE: PSR is aliased to CPSR
                # This is an artifact of the fact that Unicorn
                # seems to emulate a mash-up of M- and A-series arm.
                "psr": (unicorn.arm_const.UC_ARM_REG_CPSR, "psr", 0, 4),
                "primask": (unicorn.arm_const.UC_ARM_REG_PRIMASK, "primask", 0, 4),
                "basepri": (unicorn.arm_const.UC_ARM_REG_BASEPRI, "basepri", 0, 4),
                "faultmask": (
                    unicorn.arm_const.UC_ARM_REG_FAULTMASK,
                    "faultmask",
                    0,
                    4,
                ),
                "control": (unicorn.arm_const.UC_ARM_REG_CONTROL, "control", 0, 4),
                "msp": (unicorn.arm_const.UC_ARM_REG_MSP, "msp", 0, 4),
                "psp": (unicorn.arm_const.UC_ARM_REG_PSP, "psp", 0, 4),
            }
        )


class ARMMachineMixinRA:
    """Mixin for ARM R- or A- series machine models"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                "cpsr": (unicorn.arm_const.UC_ARM_REG_CPSR, "cpsr", 0, 4),
                "spsr": (unicorn.arm_const.UC_ARM_REG_SPSR, "spsr", 0, 4),
                # NOTE: None of the banked registers have Unicorn IDs
                "sp_usr": (unicorn.arm_const.UC_ARM_REG_INVALID, "sp_usr", 0, 4),
                "lr_usr": (unicorn.arm_const.UC_ARM_REG_INVALID, "lr_usr", 0, 4),
                "r8_usr": (unicorn.arm_const.UC_ARM_REG_INVALID, "r8_usr", 0, 4),
                "r9_usr": (unicorn.arm_const.UC_ARM_REG_INVALID, "r9_usr", 0, 4),
                "r10_usr": (unicorn.arm_const.UC_ARM_REG_INVALID, "r10_usr", 0, 4),
                "r11_usr": (unicorn.arm_const.UC_ARM_REG_INVALID, "r11_usr", 0, 4),
                "r12_usr": (unicorn.arm_const.UC_ARM_REG_INVALID, "r12_usr", 0, 4),
                "sp_hyp": (unicorn.arm_const.UC_ARM_REG_INVALID, "sp_hyp", 0, 4),
                "spsr_hyp": (unicorn.arm_const.UC_ARM_REG_INVALID, "spsr_hyp", 0, 4),
                "elr_hyp": (unicorn.arm_const.UC_ARM_REG_INVALID, "elr_hyp", 0, 4),
                "sp_svc": (unicorn.arm_const.UC_ARM_REG_INVALID, "sp_svc", 0, 4),
                "lr_svc": (unicorn.arm_const.UC_ARM_REG_INVALID, "lr_svc", 0, 4),
                "spsr_svc": (unicorn.arm_const.UC_ARM_REG_INVALID, "spsr_svc", 0, 4),
                "sp_abt": (unicorn.arm_const.UC_ARM_REG_INVALID, "sp_abt", 0, 4),
                "lr_abt": (unicorn.arm_const.UC_ARM_REG_INVALID, "lr_abt", 0, 4),
                "spsr_abt": (unicorn.arm_const.UC_ARM_REG_INVALID, "spsr_abt", 0, 4),
                "sp_und": (unicorn.arm_const.UC_ARM_REG_INVALID, "sp_und", 0, 4),
                "lr_und": (unicorn.arm_const.UC_ARM_REG_INVALID, "lr_und", 0, 4),
                "spsr_und": (unicorn.arm_const.UC_ARM_REG_INVALID, "spsr_und", 0, 4),
                "sp_mon": (unicorn.arm_const.UC_ARM_REG_INVALID, "sp_mon", 0, 4),
                "lr_mon": (unicorn.arm_const.UC_ARM_REG_INVALID, "lr_mon", 0, 4),
                "spsr_mon": (unicorn.arm_const.UC_ARM_REG_INVALID, "spsr_mon", 0, 4),
                "sp_irq": (unicorn.arm_const.UC_ARM_REG_INVALID, "sp_irq", 0, 4),
                "lr_irq": (unicorn.arm_const.UC_ARM_REG_INVALID, "lr_irq", 0, 4),
                "spsr_irq": (unicorn.arm_const.UC_ARM_REG_INVALID, "spsr_irq", 0, 4),
                "sp_fiq": (unicorn.arm_const.UC_ARM_REG_INVALID, "sp_fiq", 0, 4),
                "lr_fiq": (unicorn.arm_const.UC_ARM_REG_INVALID, "lr_fiq", 0, 4),
                "spsr_fiq": (unicorn.arm_const.UC_ARM_REG_INVALID, "spsr_fiq", 0, 4),
                "r8_fiq": (unicorn.arm_const.UC_ARM_REG_INVALID, "r8_fiq", 0, 4),
                "r9_fiq": (unicorn.arm_const.UC_ARM_REG_INVALID, "r9_fiq", 0, 4),
                "r10_fiq": (unicorn.arm_const.UC_ARM_REG_INVALID, "r10_fiq", 0, 4),
                "r11_fiq": (unicorn.arm_const.UC_ARM_REG_INVALID, "r11_fiq", 0, 4),
                "r12_fiq": (unicorn.arm_const.UC_ARM_REG_INVALID, "r12_fiq", 0, 4),
            }
        )


class ARMMachineMixinFP:
    """Mixin for ARM machine models with basic FPUs"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                "fpscr": (unicorn.arm_const.UC_ARM_REG_FPSCR, "fpscr", 0, 4),
                "fpexc": (unicorn.arm_const.UC_ARM_REG_FPEXC, "fpexc", 0, 4),
                "fpsid": (unicorn.arm_const.UC_ARM_REG_FPSID, "fpsid", 0, 4),
                "mvfr0": (unicorn.arm_const.UC_ARM_REG_INVALID, "mvfr0", 0, 4),
                "mvfr1": (unicorn.arm_const.UC_ARM_REG_INVALID, "mvfr1", 0, 4),
                "d0": (unicorn.arm_const.UC_ARM_REG_D0, "d0", 0, 8),
                "s0": (unicorn.arm_const.UC_ARM_REG_S0, "d0", 0, 4),
                "s1": (unicorn.arm_const.UC_ARM_REG_S1, "d0", 4, 4),
                "d1": (unicorn.arm_const.UC_ARM_REG_D1, "d1", 0, 8),
                "s2": (unicorn.arm_const.UC_ARM_REG_S2, "d1", 0, 4),
                "s3": (unicorn.arm_const.UC_ARM_REG_S3, "d1", 4, 4),
                "d2": (unicorn.arm_const.UC_ARM_REG_D2, "d2", 0, 8),
                "s4": (unicorn.arm_const.UC_ARM_REG_S4, "d2", 0, 4),
                "s5": (unicorn.arm_const.UC_ARM_REG_S5, "d2", 4, 4),
                "d3": (unicorn.arm_const.UC_ARM_REG_D3, "d3", 0, 8),
                "s6": (unicorn.arm_const.UC_ARM_REG_S6, "d3", 0, 4),
                "s7": (unicorn.arm_const.UC_ARM_REG_S7, "d3", 4, 4),
                "d4": (unicorn.arm_const.UC_ARM_REG_D4, "d4", 0, 8),
                "s8": (unicorn.arm_const.UC_ARM_REG_S8, "d4", 0, 4),
                "s9": (unicorn.arm_const.UC_ARM_REG_S9, "d4", 4, 4),
                "d5": (unicorn.arm_const.UC_ARM_REG_D5, "d5", 0, 8),
                "s10": (unicorn.arm_const.UC_ARM_REG_S10, "d5", 0, 4),
                "s11": (unicorn.arm_const.UC_ARM_REG_S11, "d5", 4, 4),
                "d6": (unicorn.arm_const.UC_ARM_REG_D6, "d6", 0, 8),
                "s12": (unicorn.arm_const.UC_ARM_REG_S12, "d6", 0, 4),
                "s13": (unicorn.arm_const.UC_ARM_REG_S13, "d6", 4, 4),
                "d7": (unicorn.arm_const.UC_ARM_REG_D7, "d7", 0, 8),
                "s14": (unicorn.arm_const.UC_ARM_REG_S14, "d7", 0, 4),
                "s15": (unicorn.arm_const.UC_ARM_REG_S15, "d7", 4, 4),
                "d8": (unicorn.arm_const.UC_ARM_REG_D8, "d8", 0, 8),
                "s16": (unicorn.arm_const.UC_ARM_REG_S16, "d8", 0, 4),
                "s17": (unicorn.arm_const.UC_ARM_REG_S17, "d8", 4, 4),
                "d9": (unicorn.arm_const.UC_ARM_REG_D9, "d9", 0, 8),
                "s18": (unicorn.arm_const.UC_ARM_REG_S18, "d9", 0, 4),
                "s19": (unicorn.arm_const.UC_ARM_REG_S19, "d9", 4, 4),
                "d10": (unicorn.arm_const.UC_ARM_REG_D10, "d10", 0, 8),
                "s20": (unicorn.arm_const.UC_ARM_REG_S20, "d10", 0, 4),
                "s21": (unicorn.arm_const.UC_ARM_REG_S21, "d10", 4, 4),
                "d11": (unicorn.arm_const.UC_ARM_REG_D11, "d11", 0, 8),
                "s22": (unicorn.arm_const.UC_ARM_REG_S22, "d11", 0, 4),
                "s23": (unicorn.arm_const.UC_ARM_REG_S23, "d11", 4, 4),
                "d12": (unicorn.arm_const.UC_ARM_REG_D12, "d12", 0, 8),
                "s24": (unicorn.arm_const.UC_ARM_REG_S24, "d12", 0, 4),
                "s25": (unicorn.arm_const.UC_ARM_REG_S25, "d12", 4, 4),
                "d13": (unicorn.arm_const.UC_ARM_REG_D13, "d13", 0, 8),
                "s26": (unicorn.arm_const.UC_ARM_REG_S26, "d13", 0, 4),
                "s27": (unicorn.arm_const.UC_ARM_REG_S27, "d13", 4, 4),
                "d14": (unicorn.arm_const.UC_ARM_REG_D14, "d14", 0, 8),
                "s28": (unicorn.arm_const.UC_ARM_REG_S28, "d14", 0, 4),
                "s29": (unicorn.arm_const.UC_ARM_REG_S29, "d14", 4, 4),
                "d15": (unicorn.arm_const.UC_ARM_REG_D15, "d15", 0, 8),
                "s30": (unicorn.arm_const.UC_ARM_REG_S30, "d15", 0, 4),
                "s31": (unicorn.arm_const.UC_ARM_REG_S31, "d15", 4, 4),
            }
        )


class ARMMachineMixinVFP:
    """Mixin for ARM machine models with VFP/NEON support"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                "fpscr": (unicorn.arm_const.UC_ARM_REG_FPSCR, "fpscr", 0, 4),
                "fpexc": (unicorn.arm_const.UC_ARM_REG_FPEXC, "fpexc", 0, 4),
                "fpsid": (unicorn.arm_const.UC_ARM_REG_FPSID, "fpsid", 0, 4),
                "mvfr0": (unicorn.arm_const.UC_ARM_REG_INVALID, "mvfr0", 0, 4),
                "mvfr1": (unicorn.arm_const.UC_ARM_REG_INVALID, "mvfr1", 0, 4),
                "q0": (unicorn.arm_const.UC_ARM_REG_Q0, "q0", 0, 16),
                "d0": (unicorn.arm_const.UC_ARM_REG_D0, "q0", 0, 8),
                "s0": (unicorn.arm_const.UC_ARM_REG_S0, "q0", 0, 4),
                "s1": (unicorn.arm_const.UC_ARM_REG_S1, "q0", 4, 4),
                "d1": (unicorn.arm_const.UC_ARM_REG_D1, "q0", 8, 8),
                "s2": (unicorn.arm_const.UC_ARM_REG_S2, "q0", 8, 4),
                "s3": (unicorn.arm_const.UC_ARM_REG_S3, "q0", 12, 4),
                "q1": (unicorn.arm_const.UC_ARM_REG_Q1, "q1", 0, 16),
                "d2": (unicorn.arm_const.UC_ARM_REG_D2, "q1", 0, 8),
                "s4": (unicorn.arm_const.UC_ARM_REG_S4, "q1", 0, 4),
                "s5": (unicorn.arm_const.UC_ARM_REG_S5, "q1", 4, 4),
                "d3": (unicorn.arm_const.UC_ARM_REG_D3, "q1", 8, 8),
                "s6": (unicorn.arm_const.UC_ARM_REG_S6, "q1", 8, 4),
                "s7": (unicorn.arm_const.UC_ARM_REG_S7, "q1", 12, 4),
                "q2": (unicorn.arm_const.UC_ARM_REG_Q2, "q2", 0, 16),
                "d4": (unicorn.arm_const.UC_ARM_REG_D4, "q2", 0, 8),
                "s8": (unicorn.arm_const.UC_ARM_REG_S8, "q2", 0, 4),
                "s9": (unicorn.arm_const.UC_ARM_REG_S9, "q2", 4, 4),
                "d5": (unicorn.arm_const.UC_ARM_REG_D5, "q2", 8, 8),
                "s10": (unicorn.arm_const.UC_ARM_REG_S10, "q2", 8, 4),
                "s11": (unicorn.arm_const.UC_ARM_REG_S11, "q2", 12, 4),
                "q3": (unicorn.arm_const.UC_ARM_REG_Q3, "q3", 0, 16),
                "d6": (unicorn.arm_const.UC_ARM_REG_D6, "q3", 0, 8),
                "s12": (unicorn.arm_const.UC_ARM_REG_S12, "q3", 0, 4),
                "s13": (unicorn.arm_const.UC_ARM_REG_S13, "q3", 4, 4),
                "d7": (unicorn.arm_const.UC_ARM_REG_D7, "q3", 8, 8),
                "s14": (unicorn.arm_const.UC_ARM_REG_S14, "q3", 8, 4),
                "s15": (unicorn.arm_const.UC_ARM_REG_S15, "q3", 12, 4),
                "q4": (unicorn.arm_const.UC_ARM_REG_Q4, "q4", 0, 16),
                "d8": (unicorn.arm_const.UC_ARM_REG_D8, "q4", 0, 8),
                "s16": (unicorn.arm_const.UC_ARM_REG_S16, "q4", 0, 4),
                "s17": (unicorn.arm_const.UC_ARM_REG_S17, "q4", 4, 4),
                "d9": (unicorn.arm_const.UC_ARM_REG_D9, "q4", 8, 8),
                "s18": (unicorn.arm_const.UC_ARM_REG_S18, "q4", 8, 4),
                "s19": (unicorn.arm_const.UC_ARM_REG_S19, "q4", 12, 4),
                "q5": (unicorn.arm_const.UC_ARM_REG_Q5, "q5", 0, 16),
                "d10": (unicorn.arm_const.UC_ARM_REG_D10, "q5", 0, 8),
                "s20": (unicorn.arm_const.UC_ARM_REG_S20, "q5", 0, 4),
                "s21": (unicorn.arm_const.UC_ARM_REG_S21, "q5", 4, 4),
                "d11": (unicorn.arm_const.UC_ARM_REG_D11, "q5", 8, 8),
                "s22": (unicorn.arm_const.UC_ARM_REG_S22, "q5", 8, 4),
                "s23": (unicorn.arm_const.UC_ARM_REG_S23, "q5", 12, 4),
                "q6": (unicorn.arm_const.UC_ARM_REG_Q6, "q6", 0, 16),
                "d12": (unicorn.arm_const.UC_ARM_REG_D12, "q6", 0, 8),
                "s24": (unicorn.arm_const.UC_ARM_REG_S24, "q6", 0, 4),
                "s25": (unicorn.arm_const.UC_ARM_REG_S25, "q6", 4, 4),
                "d13": (unicorn.arm_const.UC_ARM_REG_D13, "q6", 8, 8),
                "s26": (unicorn.arm_const.UC_ARM_REG_S26, "q6", 8, 4),
                "s27": (unicorn.arm_const.UC_ARM_REG_S27, "q6", 12, 4),
                "q7": (unicorn.arm_const.UC_ARM_REG_Q7, "q7", 0, 16),
                "d14": (unicorn.arm_const.UC_ARM_REG_D14, "q7", 0, 8),
                "s28": (unicorn.arm_const.UC_ARM_REG_S28, "q7", 0, 4),
                "s29": (unicorn.arm_const.UC_ARM_REG_S29, "q7", 4, 4),
                "d15": (unicorn.arm_const.UC_ARM_REG_D15, "q7", 8, 8),
                "s30": (unicorn.arm_const.UC_ARM_REG_S30, "q7", 8, 4),
                "s31": (unicorn.arm_const.UC_ARM_REG_S31, "q7", 12, 4),
                "q8": (unicorn.arm_const.UC_ARM_REG_Q8, "q8", 0, 16),
                "d16": (unicorn.arm_const.UC_ARM_REG_D16, "q8", 0, 8),
                "d17": (unicorn.arm_const.UC_ARM_REG_D17, "q8", 8, 8),
                "q9": (unicorn.arm_const.UC_ARM_REG_Q9, "q9", 0, 16),
                "d18": (unicorn.arm_const.UC_ARM_REG_D18, "q9", 0, 8),
                "d19": (unicorn.arm_const.UC_ARM_REG_D19, "q9", 8, 8),
                "q10": (unicorn.arm_const.UC_ARM_REG_Q10, "q10", 0, 16),
                "d20": (unicorn.arm_const.UC_ARM_REG_D20, "q10", 0, 8),
                "d21": (unicorn.arm_const.UC_ARM_REG_D21, "q10", 8, 8),
                "q11": (unicorn.arm_const.UC_ARM_REG_Q11, "q11", 0, 16),
                "d22": (unicorn.arm_const.UC_ARM_REG_D22, "q11", 0, 8),
                "d23": (unicorn.arm_const.UC_ARM_REG_D23, "q11", 8, 8),
                "q12": (unicorn.arm_const.UC_ARM_REG_Q12, "q12", 0, 16),
                "d24": (unicorn.arm_const.UC_ARM_REG_D24, "q12", 0, 8),
                "d25": (unicorn.arm_const.UC_ARM_REG_D25, "q12", 8, 8),
                "q13": (unicorn.arm_const.UC_ARM_REG_Q13, "q13", 0, 16),
                "d26": (unicorn.arm_const.UC_ARM_REG_D26, "q13", 0, 8),
                "d27": (unicorn.arm_const.UC_ARM_REG_D27, "q13", 8, 8),
                "q14": (unicorn.arm_const.UC_ARM_REG_Q14, "q14", 0, 16),
                "d28": (unicorn.arm_const.UC_ARM_REG_D28, "q14", 0, 8),
                "d29": (unicorn.arm_const.UC_ARM_REG_D29, "q14", 8, 8),
                "q15": (unicorn.arm_const.UC_ARM_REG_Q15, "q15", 0, 16),
                "d30": (unicorn.arm_const.UC_ARM_REG_D30, "q15", 0, 8),
                "d31": (unicorn.arm_const.UC_ARM_REG_D31, "q15", 8, 8),
            }
        )


class ARMv5TMachineDef(ARMMachineMixinM, ARMMachineDef):
    """Unicorn machine definition for ARMv5T little-endian"""

    arch = Architecture.ARM_V5T
    byteorder = Byteorder.LITTLE


class ARMv6MMachineDef(ARMMachineMixinFP, ARMMachineMixinM, ARMMachineDef):
    """Unicorn machine definition for ARMv6-M little-endian"""

    arch = Architecture.ARM_V6M
    byteorder = Byteorder.LITTLE


class ARMv6MThumbMachineDef(ARMv6MMachineDef):
    """Unicorn machine definition for ARMv6-M little-endian, THUMB ISA"""

    arch = Architecture.ARM_V6M_THUMB
    uc_mode = unicorn.UC_MODE_THUMB
    cs_mode = capstone.CS_MODE_THUMB


class ARMv7MMachineDef(ARMMachineMixinFP, ARMMachineMixinM, ARMMachineDef):
    """Unicorn machine definition for ARMv7-M little-endian"""

    arch = Architecture.ARM_V7M
    byteorder = Byteorder.LITTLE


class ARMv7RMachineDef(ARMMachineMixinVFP, ARMMachineMixinRA, ARMMachineDef):
    """Unicorn machine definition for ARMv7-R little-endian"""

    arch = Architecture.ARM_V7R
    byteorder = Byteorder.LITTLE


class ARMv7AMachineDef(ARMMachineMixinVFP, ARMMachineMixinRA, ARMMachineDef):
    """Unicorn machine definition for ARMv7-A little-endian"""

    arch = Architecture.ARM_V7A
    byteorder = Byteorder.LITTLE
