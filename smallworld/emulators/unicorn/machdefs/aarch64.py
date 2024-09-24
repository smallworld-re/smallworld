import capstone
import unicorn

from .machdef import UnicornMachineDef
from ....platforms import Byteorder


class AArch64MachineDef(UnicornMachineDef):
    arch = "aarch64"
    mode = "v8a"
    byteorder = Byteorder.LITTLE

    uc_arch = unicorn.UC_ARCH_ARM64
    uc_mode = unicorn.UC_MODE_ARM

    cs_arch = capstone.CS_ARCH_ARM64
    cs_mode = capstone.CS_MODE_ARM

    pc_reg = "pc"

    _registers = {
        "x0": unicorn.arm64_const.UC_ARM64_REG_X0,
        "w0": unicorn.arm64_const.UC_ARM64_REG_W0,
        "x1": unicorn.arm64_const.UC_ARM64_REG_X1,
        "w1": unicorn.arm64_const.UC_ARM64_REG_W1,
        "x2": unicorn.arm64_const.UC_ARM64_REG_X2,
        "w2": unicorn.arm64_const.UC_ARM64_REG_W2,
        "x3": unicorn.arm64_const.UC_ARM64_REG_X3,
        "w3": unicorn.arm64_const.UC_ARM64_REG_W3,
        "x4": unicorn.arm64_const.UC_ARM64_REG_X4,
        "w4": unicorn.arm64_const.UC_ARM64_REG_W4,
        "x5": unicorn.arm64_const.UC_ARM64_REG_X5,
        "w5": unicorn.arm64_const.UC_ARM64_REG_W5,
        "x6": unicorn.arm64_const.UC_ARM64_REG_X6,
        "w6": unicorn.arm64_const.UC_ARM64_REG_W6,
        "x7": unicorn.arm64_const.UC_ARM64_REG_X7,
        "w7": unicorn.arm64_const.UC_ARM64_REG_W7,
        "x8": unicorn.arm64_const.UC_ARM64_REG_X8,
        "w8": unicorn.arm64_const.UC_ARM64_REG_W8,
        "x9": unicorn.arm64_const.UC_ARM64_REG_X9,
        "w9": unicorn.arm64_const.UC_ARM64_REG_W9,
        "x10": unicorn.arm64_const.UC_ARM64_REG_X10,
        "w10": unicorn.arm64_const.UC_ARM64_REG_W10,
        "x11": unicorn.arm64_const.UC_ARM64_REG_X11,
        "w11": unicorn.arm64_const.UC_ARM64_REG_W11,
        "x12": unicorn.arm64_const.UC_ARM64_REG_X12,
        "w12": unicorn.arm64_const.UC_ARM64_REG_W12,
        "x13": unicorn.arm64_const.UC_ARM64_REG_X13,
        "w13": unicorn.arm64_const.UC_ARM64_REG_W13,
        "x14": unicorn.arm64_const.UC_ARM64_REG_X14,
        "w14": unicorn.arm64_const.UC_ARM64_REG_W14,
        "x15": unicorn.arm64_const.UC_ARM64_REG_X15,
        "w15": unicorn.arm64_const.UC_ARM64_REG_W15,
        "x16": unicorn.arm64_const.UC_ARM64_REG_X16,
        "w16": unicorn.arm64_const.UC_ARM64_REG_W16,
        "x17": unicorn.arm64_const.UC_ARM64_REG_X17,
        "w17": unicorn.arm64_const.UC_ARM64_REG_W17,
        "x18": unicorn.arm64_const.UC_ARM64_REG_X18,
        "w18": unicorn.arm64_const.UC_ARM64_REG_W18,
        "x19": unicorn.arm64_const.UC_ARM64_REG_X19,
        "w19": unicorn.arm64_const.UC_ARM64_REG_W19,
        "x20": unicorn.arm64_const.UC_ARM64_REG_X20,
        "w20": unicorn.arm64_const.UC_ARM64_REG_W20,
        "x21": unicorn.arm64_const.UC_ARM64_REG_X21,
        "w21": unicorn.arm64_const.UC_ARM64_REG_W21,
        "x22": unicorn.arm64_const.UC_ARM64_REG_X22,
        "w22": unicorn.arm64_const.UC_ARM64_REG_W22,
        "x23": unicorn.arm64_const.UC_ARM64_REG_X23,
        "w23": unicorn.arm64_const.UC_ARM64_REG_W23,
        "x24": unicorn.arm64_const.UC_ARM64_REG_X24,
        "w24": unicorn.arm64_const.UC_ARM64_REG_W24,
        "x25": unicorn.arm64_const.UC_ARM64_REG_X25,
        "w25": unicorn.arm64_const.UC_ARM64_REG_W25,
        "x26": unicorn.arm64_const.UC_ARM64_REG_X26,
        "w26": unicorn.arm64_const.UC_ARM64_REG_W26,
        "x27": unicorn.arm64_const.UC_ARM64_REG_X27,
        "w27": unicorn.arm64_const.UC_ARM64_REG_W27,
        "x28": unicorn.arm64_const.UC_ARM64_REG_X28,
        "w28": unicorn.arm64_const.UC_ARM64_REG_W28,
        "x29": unicorn.arm64_const.UC_ARM64_REG_X29,
        "w29": unicorn.arm64_const.UC_ARM64_REG_W29,
        "x30": unicorn.arm64_const.UC_ARM64_REG_X30,
        "w30": unicorn.arm64_const.UC_ARM64_REG_W30,
        # *** Special Registers ***
        # Program Counter
        "pc": unicorn.arm64_const.UC_ARM64_REG_PC,
        # Stack Pointer
        "sp": unicorn.arm64_const.UC_ARM64_REG_SP,
        "wsp": unicorn.arm64_const.UC_ARM64_REG_WSP,
        # fp: Frame pointer; alias for x29
        "fp": unicorn.arm64_const.UC_ARM64_REG_FP,
        # lr: Link register; alias for x30
        "lr": unicorn.arm64_const.UC_ARM64_REG_LR,
        # Zero Register
        "xzr": unicorn.arm64_const.UC_ARM64_REG_XZR,
        "wzr": unicorn.arm64_const.UC_ARM64_REG_WZR,
        # sp_elX: Banked stack pointers for exception handlers
        "sp_el0": unicorn.arm64_const.UC_ARM64_REG_SP_EL0,
        "sp_el1": unicorn.arm64_const.UC_ARM64_REG_SP_EL1,
        "sp_el2": unicorn.arm64_const.UC_ARM64_REG_SP_EL2,
        "sp_el3": unicorn.arm64_const.UC_ARM64_REG_SP_EL3,
        # *** System Registers ***
        # NOTE: Here, the name indicates the lowest EL that can access the register.
        # NOTE: The Unicorn model is missing a boatload of other system control registers.
        # Condition code register
        "fpcr": unicorn.arm64_const.UC_ARM64_REG_FPCR,
        # Floating Point Status Register
        "fpsr": unicorn.arm64_const.UC_ARM64_REG_FPSR,
        # elr_elX: Banked Exception Link Registers for exception handlers.
        # TODO: Unicorn lists an "elr_el0", but the AArch64 docs don't...
        "elr_el1": unicorn.arm64_const.UC_ARM64_REG_ELR_EL1,
        "elr_el2": unicorn.arm64_const.UC_ARM64_REG_ELR_EL2,
        "elr_el3": unicorn.arm64_const.UC_ARM64_REG_ELR_EL3,
        # esr_elX: Banked Exception Syndrome Registers for exception handlers.
        # TODO: Unicorn lists an "esr_el0", but the AArch64 docs don't...
        "esr_el1": unicorn.arm64_const.UC_ARM64_REG_ESR_EL1,
        "esr_el2": unicorn.arm64_const.UC_ARM64_REG_ESR_EL2,
        "esr_el3": unicorn.arm64_const.UC_ARM64_REG_ESR_EL3,
        # far_elX: Banked Fault Address Registers for exception handlers.
        # TODO: Unicorn lists a "far_el0", but the AArch64 docs don't...
        "far_el1": unicorn.arm64_const.UC_ARM64_REG_FAR_EL1,
        "far_el2": unicorn.arm64_const.UC_ARM64_REG_FAR_EL2,
        "far_el3": unicorn.arm64_const.UC_ARM64_REG_FAR_EL3,
        # vbar_elX: Banked Vector Base Address Registers for exception handlers
        "vbar_el1": unicorn.arm64_const.UC_ARM64_REG_VBAR_EL1,
        # NOTE: vbar_el0 and vbar_el1 are aliases for each other.
        # The Sleigh model only recognizes vbar_el1,
        # so it needs to be the "real" copy.
        "vbar_el0": unicorn.arm64_const.UC_ARM64_REG_VBAR_EL0,
        "vbar_el2": unicorn.arm64_const.UC_ARM64_REG_VBAR_EL2,
        "vbar_el3": unicorn.arm64_const.UC_ARM64_REG_VBAR_EL3,
        # Coprocessor Access Control Register
        "cpacr_el1": unicorn.arm64_const.UC_ARM64_REG_CPACR_EL1,
        # Memory Attribute Indirection Register
        # NOTE: There should be four of these.
        "mair_el1": unicorn.arm64_const.UC_ARM64_REG_MAIR_EL1,
        # Physical Address Register
        "par_el1": unicorn.arm64_const.UC_ARM64_REG_PAR_EL1,
        # Translation Table Zero Base Register
        "ttbr0_el1": unicorn.arm64_const.UC_ARM64_REG_TTBR0_EL1,
        # Translation Table One Base Register
        "ttbr1_el1": unicorn.arm64_const.UC_ARM64_REG_TTBR1_EL1,
        # Thread ID Register
        # NOTE: There should be four of these.
        "tpidr_el0": unicorn.arm64_const.UC_ARM64_REG_TPIDR_EL0,
        "tpidr_el1": unicorn.arm64_const.UC_ARM64_REG_TPIDR_EL1,
        # Userspace-visible Thread ID register
        "tpidrro_el0": unicorn.arm64_const.UC_ARM64_REG_TPIDRRO_EL0,
        "q0": unicorn.arm64_const.UC_ARM64_REG_Q0,
        "d0": unicorn.arm64_const.UC_ARM64_REG_D0,
        "s0": unicorn.arm64_const.UC_ARM64_REG_S0,
        "h0": unicorn.arm64_const.UC_ARM64_REG_H0,
        "b0": unicorn.arm64_const.UC_ARM64_REG_B0,
        "q1": unicorn.arm64_const.UC_ARM64_REG_Q1,
        "d1": unicorn.arm64_const.UC_ARM64_REG_D1,
        "s1": unicorn.arm64_const.UC_ARM64_REG_S1,
        "h1": unicorn.arm64_const.UC_ARM64_REG_H1,
        "b1": unicorn.arm64_const.UC_ARM64_REG_B1,
        "q2": unicorn.arm64_const.UC_ARM64_REG_Q2,
        "d2": unicorn.arm64_const.UC_ARM64_REG_D2,
        "s2": unicorn.arm64_const.UC_ARM64_REG_S2,
        "h2": unicorn.arm64_const.UC_ARM64_REG_H2,
        "b2": unicorn.arm64_const.UC_ARM64_REG_B2,
        "q3": unicorn.arm64_const.UC_ARM64_REG_Q3,
        "d3": unicorn.arm64_const.UC_ARM64_REG_D3,
        "s3": unicorn.arm64_const.UC_ARM64_REG_S3,
        "h3": unicorn.arm64_const.UC_ARM64_REG_H3,
        "b3": unicorn.arm64_const.UC_ARM64_REG_B3,
        "q4": unicorn.arm64_const.UC_ARM64_REG_Q4,
        "d4": unicorn.arm64_const.UC_ARM64_REG_D4,
        "s4": unicorn.arm64_const.UC_ARM64_REG_S4,
        "h4": unicorn.arm64_const.UC_ARM64_REG_H4,
        "b4": unicorn.arm64_const.UC_ARM64_REG_B4,
        "q5": unicorn.arm64_const.UC_ARM64_REG_Q5,
        "d5": unicorn.arm64_const.UC_ARM64_REG_D5,
        "s5": unicorn.arm64_const.UC_ARM64_REG_S5,
        "h5": unicorn.arm64_const.UC_ARM64_REG_H5,
        "b5": unicorn.arm64_const.UC_ARM64_REG_B5,
        "q6": unicorn.arm64_const.UC_ARM64_REG_Q6,
        "d6": unicorn.arm64_const.UC_ARM64_REG_D6,
        "s6": unicorn.arm64_const.UC_ARM64_REG_S6,
        "h6": unicorn.arm64_const.UC_ARM64_REG_H6,
        "b6": unicorn.arm64_const.UC_ARM64_REG_B6,
        "q7": unicorn.arm64_const.UC_ARM64_REG_Q7,
        "d7": unicorn.arm64_const.UC_ARM64_REG_D7,
        "s7": unicorn.arm64_const.UC_ARM64_REG_S7,
        "h7": unicorn.arm64_const.UC_ARM64_REG_H7,
        "b7": unicorn.arm64_const.UC_ARM64_REG_B7,
        "q8": unicorn.arm64_const.UC_ARM64_REG_Q8,
        "d8": unicorn.arm64_const.UC_ARM64_REG_D8,
        "s8": unicorn.arm64_const.UC_ARM64_REG_S8,
        "h8": unicorn.arm64_const.UC_ARM64_REG_H8,
        "b8": unicorn.arm64_const.UC_ARM64_REG_B8,
        "q9": unicorn.arm64_const.UC_ARM64_REG_Q9,
        "d9": unicorn.arm64_const.UC_ARM64_REG_D9,
        "s9": unicorn.arm64_const.UC_ARM64_REG_S9,
        "h9": unicorn.arm64_const.UC_ARM64_REG_H9,
        "b9": unicorn.arm64_const.UC_ARM64_REG_B9,
        "q10": unicorn.arm64_const.UC_ARM64_REG_Q10,
        "d10": unicorn.arm64_const.UC_ARM64_REG_D10,
        "s10": unicorn.arm64_const.UC_ARM64_REG_S10,
        "h10": unicorn.arm64_const.UC_ARM64_REG_H10,
        "b10": unicorn.arm64_const.UC_ARM64_REG_B10,
        "q11": unicorn.arm64_const.UC_ARM64_REG_Q11,
        "d11": unicorn.arm64_const.UC_ARM64_REG_D11,
        "s11": unicorn.arm64_const.UC_ARM64_REG_S11,
        "h11": unicorn.arm64_const.UC_ARM64_REG_H11,
        "b11": unicorn.arm64_const.UC_ARM64_REG_B11,
        "q12": unicorn.arm64_const.UC_ARM64_REG_Q12,
        "d12": unicorn.arm64_const.UC_ARM64_REG_D12,
        "s12": unicorn.arm64_const.UC_ARM64_REG_S12,
        "h12": unicorn.arm64_const.UC_ARM64_REG_H12,
        "b12": unicorn.arm64_const.UC_ARM64_REG_B12,
        "q13": unicorn.arm64_const.UC_ARM64_REG_Q13,
        "d13": unicorn.arm64_const.UC_ARM64_REG_D13,
        "s13": unicorn.arm64_const.UC_ARM64_REG_S13,
        "h13": unicorn.arm64_const.UC_ARM64_REG_H13,
        "b13": unicorn.arm64_const.UC_ARM64_REG_B13,
        "q14": unicorn.arm64_const.UC_ARM64_REG_Q14,
        "d14": unicorn.arm64_const.UC_ARM64_REG_D14,
        "s14": unicorn.arm64_const.UC_ARM64_REG_S14,
        "h14": unicorn.arm64_const.UC_ARM64_REG_H14,
        "b14": unicorn.arm64_const.UC_ARM64_REG_B14,
        "q15": unicorn.arm64_const.UC_ARM64_REG_Q15,
        "d15": unicorn.arm64_const.UC_ARM64_REG_D15,
        "s15": unicorn.arm64_const.UC_ARM64_REG_S15,
        "h15": unicorn.arm64_const.UC_ARM64_REG_H15,
        "b15": unicorn.arm64_const.UC_ARM64_REG_B15,
        "q16": unicorn.arm64_const.UC_ARM64_REG_Q16,
        "d16": unicorn.arm64_const.UC_ARM64_REG_D16,
        "s16": unicorn.arm64_const.UC_ARM64_REG_S16,
        "h16": unicorn.arm64_const.UC_ARM64_REG_H16,
        "b16": unicorn.arm64_const.UC_ARM64_REG_B16,
        "q17": unicorn.arm64_const.UC_ARM64_REG_Q17,
        "d17": unicorn.arm64_const.UC_ARM64_REG_D17,
        "s17": unicorn.arm64_const.UC_ARM64_REG_S17,
        "h17": unicorn.arm64_const.UC_ARM64_REG_H17,
        "b17": unicorn.arm64_const.UC_ARM64_REG_B17,
        "q18": unicorn.arm64_const.UC_ARM64_REG_Q18,
        "d18": unicorn.arm64_const.UC_ARM64_REG_D18,
        "s18": unicorn.arm64_const.UC_ARM64_REG_S18,
        "h18": unicorn.arm64_const.UC_ARM64_REG_H18,
        "b18": unicorn.arm64_const.UC_ARM64_REG_B18,
        "q19": unicorn.arm64_const.UC_ARM64_REG_Q19,
        "d19": unicorn.arm64_const.UC_ARM64_REG_D19,
        "s19": unicorn.arm64_const.UC_ARM64_REG_S19,
        "h19": unicorn.arm64_const.UC_ARM64_REG_H19,
        "b19": unicorn.arm64_const.UC_ARM64_REG_B19,
        "q20": unicorn.arm64_const.UC_ARM64_REG_Q20,
        "d20": unicorn.arm64_const.UC_ARM64_REG_D20,
        "s20": unicorn.arm64_const.UC_ARM64_REG_S20,
        "h20": unicorn.arm64_const.UC_ARM64_REG_H20,
        "b20": unicorn.arm64_const.UC_ARM64_REG_B20,
        "q21": unicorn.arm64_const.UC_ARM64_REG_Q21,
        "d21": unicorn.arm64_const.UC_ARM64_REG_D21,
        "s21": unicorn.arm64_const.UC_ARM64_REG_S21,
        "h21": unicorn.arm64_const.UC_ARM64_REG_H21,
        "b21": unicorn.arm64_const.UC_ARM64_REG_B21,
        "q22": unicorn.arm64_const.UC_ARM64_REG_Q22,
        "d22": unicorn.arm64_const.UC_ARM64_REG_D22,
        "s22": unicorn.arm64_const.UC_ARM64_REG_S22,
        "h22": unicorn.arm64_const.UC_ARM64_REG_H22,
        "b22": unicorn.arm64_const.UC_ARM64_REG_B22,
        "q23": unicorn.arm64_const.UC_ARM64_REG_Q23,
        "d23": unicorn.arm64_const.UC_ARM64_REG_D23,
        "s23": unicorn.arm64_const.UC_ARM64_REG_S23,
        "h23": unicorn.arm64_const.UC_ARM64_REG_H23,
        "b23": unicorn.arm64_const.UC_ARM64_REG_B23,
        "q24": unicorn.arm64_const.UC_ARM64_REG_Q24,
        "d24": unicorn.arm64_const.UC_ARM64_REG_D24,
        "s24": unicorn.arm64_const.UC_ARM64_REG_S24,
        "h24": unicorn.arm64_const.UC_ARM64_REG_H24,
        "b24": unicorn.arm64_const.UC_ARM64_REG_B24,
        "q25": unicorn.arm64_const.UC_ARM64_REG_Q25,
        "d25": unicorn.arm64_const.UC_ARM64_REG_D25,
        "s25": unicorn.arm64_const.UC_ARM64_REG_S25,
        "h25": unicorn.arm64_const.UC_ARM64_REG_H25,
        "b25": unicorn.arm64_const.UC_ARM64_REG_B25,
        "q26": unicorn.arm64_const.UC_ARM64_REG_Q26,
        "d26": unicorn.arm64_const.UC_ARM64_REG_D26,
        "s26": unicorn.arm64_const.UC_ARM64_REG_S26,
        "h26": unicorn.arm64_const.UC_ARM64_REG_H26,
        "b26": unicorn.arm64_const.UC_ARM64_REG_B26,
        "q27": unicorn.arm64_const.UC_ARM64_REG_Q27,
        "d27": unicorn.arm64_const.UC_ARM64_REG_D27,
        "s27": unicorn.arm64_const.UC_ARM64_REG_S27,
        "h27": unicorn.arm64_const.UC_ARM64_REG_H27,
        "b27": unicorn.arm64_const.UC_ARM64_REG_B27,
        "q28": unicorn.arm64_const.UC_ARM64_REG_Q28,
        "d28": unicorn.arm64_const.UC_ARM64_REG_D28,
        "s28": unicorn.arm64_const.UC_ARM64_REG_S28,
        "h28": unicorn.arm64_const.UC_ARM64_REG_H28,
        "b28": unicorn.arm64_const.UC_ARM64_REG_B28,
        "q29": unicorn.arm64_const.UC_ARM64_REG_Q29,
        "d29": unicorn.arm64_const.UC_ARM64_REG_D29,
        "s29": unicorn.arm64_const.UC_ARM64_REG_S29,
        "h29": unicorn.arm64_const.UC_ARM64_REG_H29,
        "b29": unicorn.arm64_const.UC_ARM64_REG_B29,
        "q30": unicorn.arm64_const.UC_ARM64_REG_Q30,
        "d30": unicorn.arm64_const.UC_ARM64_REG_D30,
        "s30": unicorn.arm64_const.UC_ARM64_REG_S30,
        "h30": unicorn.arm64_const.UC_ARM64_REG_H30,
        "b30": unicorn.arm64_const.UC_ARM64_REG_B30,
        "q31": unicorn.arm64_const.UC_ARM64_REG_Q31,
        "d31": unicorn.arm64_const.UC_ARM64_REG_D31,
        "s31": unicorn.arm64_const.UC_ARM64_REG_S31,
        "h31": unicorn.arm64_const.UC_ARM64_REG_H31,
        "b31": unicorn.arm64_const.UC_ARM64_REG_B31,
    }
