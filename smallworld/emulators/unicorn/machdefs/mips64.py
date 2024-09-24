import capstone
import unicorn

from .machdef import UnicornMachineDef
from ....platforms import Byteorder


class MIPS64ELMachineDef(UnicornMachineDef):
    """Unicorn machine definition for mips64 little-endian"""

    arch = "mips"
    mode = "mips64"
    byteorder = Byteorder.LITTLE

    uc_arch = unicorn.UC_ARCH_MIPS
    uc_mode = unicorn.UC_MODE_MIPS64

    cs_arch = capstone.CS_ARCH_MIPS
    cs_mode = capstone.CS_MODE_MIPS64

    pc_reg = "pc"

    _registers = {
        # *** General-Purpose Registers ***
        # Assembler Temporary Register
        "at": unicorn.mips_const.UC_MIPS_REG_AT,
        "1": unicorn.mips_const.UC_MIPS_REG_1,
        # Return Value Registers
        "v0": unicorn.mips_const.UC_MIPS_REG_V0,
        "2": unicorn.mips_const.UC_MIPS_REG_2,
        "v1": unicorn.mips_const.UC_MIPS_REG_V1,
        "3": unicorn.mips_const.UC_MIPS_REG_3,
        # Argument Registers
        "a0": unicorn.mips_const.UC_MIPS_REG_A0,
        "4": unicorn.mips_const.UC_MIPS_REG_4,
        "a1": unicorn.mips_const.UC_MIPS_REG_A1,
        "5": unicorn.mips_const.UC_MIPS_REG_5,
        "a2": unicorn.mips_const.UC_MIPS_REG_A2,
        "6": unicorn.mips_const.UC_MIPS_REG_6,
        "a3": unicorn.mips_const.UC_MIPS_REG_A3,
        "7": unicorn.mips_const.UC_MIPS_REG_7,
        # Temporary Registers
        "t0": unicorn.mips_const.UC_MIPS_REG_T0,
        "8": unicorn.mips_const.UC_MIPS_REG_8,
        "t1": unicorn.mips_const.UC_MIPS_REG_T1,
        "9": unicorn.mips_const.UC_MIPS_REG_9,
        "t2": unicorn.mips_const.UC_MIPS_REG_T2,
        "10": unicorn.mips_const.UC_MIPS_REG_10,
        "t3": unicorn.mips_const.UC_MIPS_REG_T3,
        "11": unicorn.mips_const.UC_MIPS_REG_11,
        "t4": unicorn.mips_const.UC_MIPS_REG_T4,
        "12": unicorn.mips_const.UC_MIPS_REG_12,
        "t5": unicorn.mips_const.UC_MIPS_REG_T5,
        "13": unicorn.mips_const.UC_MIPS_REG_13,
        "t6": unicorn.mips_const.UC_MIPS_REG_T6,
        "14": unicorn.mips_const.UC_MIPS_REG_14,
        "t7": unicorn.mips_const.UC_MIPS_REG_T7,
        "15": unicorn.mips_const.UC_MIPS_REG_15,
        "t8": unicorn.mips_const.UC_MIPS_REG_T8,
        "24": unicorn.mips_const.UC_MIPS_REG_24,
        "t9": unicorn.mips_const.UC_MIPS_REG_T9,
        "25": unicorn.mips_const.UC_MIPS_REG_25,
        # Saved Registers
        "s0": unicorn.mips_const.UC_MIPS_REG_S0,
        "16": unicorn.mips_const.UC_MIPS_REG_16,
        "s1": unicorn.mips_const.UC_MIPS_REG_S1,
        "17": unicorn.mips_const.UC_MIPS_REG_17,
        "s2": unicorn.mips_const.UC_MIPS_REG_S2,
        "18": unicorn.mips_const.UC_MIPS_REG_18,
        "s3": unicorn.mips_const.UC_MIPS_REG_S3,
        "19": unicorn.mips_const.UC_MIPS_REG_19,
        "s4": unicorn.mips_const.UC_MIPS_REG_S4,
        "20": unicorn.mips_const.UC_MIPS_REG_20,
        "s5": unicorn.mips_const.UC_MIPS_REG_S5,
        "21": unicorn.mips_const.UC_MIPS_REG_21,
        "s6": unicorn.mips_const.UC_MIPS_REG_S6,
        "22": unicorn.mips_const.UC_MIPS_REG_22,
        "s7": unicorn.mips_const.UC_MIPS_REG_S7,
        "23": unicorn.mips_const.UC_MIPS_REG_23,
        # NOTE: Register 30 used to be FP, is now also s8
        "s8": unicorn.mips_const.UC_MIPS_REG_S8,
        "fp": unicorn.mips_const.UC_MIPS_REG_FP,
        "30": unicorn.mips_const.UC_MIPS_REG_30,
        # Kernel-reserved registers
        "k0": unicorn.mips_const.UC_MIPS_REG_K0,
        "26": unicorn.mips_const.UC_MIPS_REG_26,
        "k1": unicorn.mips_const.UC_MIPS_REG_K1,
        "27": unicorn.mips_const.UC_MIPS_REG_27,
        # *** Pointer Registers ***
        # Zero Register
        "zero": unicorn.mips_const.UC_MIPS_REG_ZERO,
        "0": unicorn.mips_const.UC_MIPS_REG_0,
        # Global Pointer Register
        "gp": unicorn.mips_const.UC_MIPS_REG_GP,
        "28": unicorn.mips_const.UC_MIPS_REG_28,
        # Stack Pointer Register
        "sp": unicorn.mips_const.UC_MIPS_REG_SP,
        "29": unicorn.mips_const.UC_MIPS_REG_29,
        # Return Address Register
        "ra": unicorn.mips_const.UC_MIPS_REG_RA,
        "31": unicorn.mips_const.UC_MIPS_REG_31,
        # Program Counter
        "pc": unicorn.mips_const.UC_MIPS_REG_PC,
        # *** Floating-point Registers ***
        "f0": unicorn.mips_const.UC_MIPS_REG_F0,
        "f1": unicorn.mips_const.UC_MIPS_REG_F1,
        "f2": unicorn.mips_const.UC_MIPS_REG_F2,
        "f3": unicorn.mips_const.UC_MIPS_REG_F3,
        "f4": unicorn.mips_const.UC_MIPS_REG_F4,
        "f5": unicorn.mips_const.UC_MIPS_REG_F5,
        "f6": unicorn.mips_const.UC_MIPS_REG_F6,
        "f7": unicorn.mips_const.UC_MIPS_REG_F7,
        "f8": unicorn.mips_const.UC_MIPS_REG_F8,
        "f9": unicorn.mips_const.UC_MIPS_REG_F9,
        "f10": unicorn.mips_const.UC_MIPS_REG_F10,
        "f11": unicorn.mips_const.UC_MIPS_REG_F11,
        "f12": unicorn.mips_const.UC_MIPS_REG_F12,
        "f13": unicorn.mips_const.UC_MIPS_REG_F13,
        "f14": unicorn.mips_const.UC_MIPS_REG_F14,
        "f15": unicorn.mips_const.UC_MIPS_REG_F15,
        "f16": unicorn.mips_const.UC_MIPS_REG_F16,
        "f17": unicorn.mips_const.UC_MIPS_REG_F17,
        "f18": unicorn.mips_const.UC_MIPS_REG_F18,
        "f19": unicorn.mips_const.UC_MIPS_REG_F19,
        "f20": unicorn.mips_const.UC_MIPS_REG_F20,
        "f21": unicorn.mips_const.UC_MIPS_REG_F21,
        "f22": unicorn.mips_const.UC_MIPS_REG_F22,
        "f23": unicorn.mips_const.UC_MIPS_REG_F23,
        "f24": unicorn.mips_const.UC_MIPS_REG_F24,
        "f25": unicorn.mips_const.UC_MIPS_REG_F25,
        "f26": unicorn.mips_const.UC_MIPS_REG_F26,
        "f27": unicorn.mips_const.UC_MIPS_REG_F27,
        "f28": unicorn.mips_const.UC_MIPS_REG_F28,
        "f29": unicorn.mips_const.UC_MIPS_REG_F29,
        "f30": unicorn.mips_const.UC_MIPS_REG_F30,
        "f31": unicorn.mips_const.UC_MIPS_REG_F31,
        # *** Floating Point Control Registers ***
        # NOTE: These are taken from Sleigh, and the MIPS docs.
        # Unicorn doesn't use these names, and has a different number of registers.
        "fir": unicorn.mips_const.UC_MIPS_REG_INVALID,
        "fcsr": unicorn.mips_const.UC_MIPS_REG_INVALID,
        "fexr": unicorn.mips_const.UC_MIPS_REG_INVALID,
        "fenr": unicorn.mips_const.UC_MIPS_REG_INVALID,
        "fccr": unicorn.mips_const.UC_MIPS_REG_INVALID,
        # *** Accumulator Registers ***
        "ac0": unicorn.mips_const.UC_MIPS_REG_AC0,
        "hi0": unicorn.mips_const.UC_MIPS_REG_HI0,
        "lo0": unicorn.mips_const.UC_MIPS_REG_LO0,
        "ac1": unicorn.mips_const.UC_MIPS_REG_AC1,
        "hi1": unicorn.mips_const.UC_MIPS_REG_HI1,
        "lo1": unicorn.mips_const.UC_MIPS_REG_LO1,
        "ac2": unicorn.mips_const.UC_MIPS_REG_AC2,
        "hi2": unicorn.mips_const.UC_MIPS_REG_HI2,
        "lo2": unicorn.mips_const.UC_MIPS_REG_LO2,
        "ac3": unicorn.mips_const.UC_MIPS_REG_AC3,
        "hi3": unicorn.mips_const.UC_MIPS_REG_HI3,
        "lo3": unicorn.mips_const.UC_MIPS_REG_LO3,
    }


class MIPS64BEMachineDef(MIPS64ELMachineDef):
    """Unicorn machine definition for mips64 big-endian

    While big and little byteorder have differences in register layout,
    the names are identical.
    """

    byteorder = "big"

    uc_mode = unicorn.UC_MODE_MIPS64 | unicorn.UC_MODE_BIG_ENDIAN

    cs_mode = capstone.CS_MODE_MIPS64 | capstone.CS_MODE_BIG_ENDIAN
