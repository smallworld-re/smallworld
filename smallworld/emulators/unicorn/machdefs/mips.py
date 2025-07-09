import unicorn

from ....platforms import Architecture, Byteorder
from .machdef import UnicornMachineDef


class MIPSMachineDef(UnicornMachineDef):
    """Unicorn machine definition for mips32"""

    arch = Architecture.MIPS32

    uc_arch = unicorn.UC_ARCH_MIPS
    uc_mode = unicorn.UC_MODE_MIPS32

    def __init__(self):
        self._registers = {
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
            "f0": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f1": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f2": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f3": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f4": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f5": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f6": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f7": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f8": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f9": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f10": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f11": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f12": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f13": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f14": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f15": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f16": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f17": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f18": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f19": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f20": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f21": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f22": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f23": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f24": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f25": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f26": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f27": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f28": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f29": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f30": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "f31": unicorn.mips_const.UC_MIPS_REG_INVALID,
            # *** Floating Point Control Registers ***
            # NOTE: These are taken from Sleigh, and the MIPS docs.
            # Unicorn doesn't use these names, and has a different number of registers.
            "fir": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "fcsr": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "fexr": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "fenr": unicorn.mips_const.UC_MIPS_REG_INVALID,
            "fccr": unicorn.mips_const.UC_MIPS_REG_INVALID,
        }


class MIPSELMachineDef(MIPSMachineDef):
    """Unicorn machine definition for mips32 little-endian"""

    byteorder = Byteorder.LITTLE

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # *** Accumulator Registers ***
                # TODO: Unicorn broke support for these in 2.0.2
                "ac0": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "lo0": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "hi0": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "ac1": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "lo1": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "hi1": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "ac2": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "lo2": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "hi2": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "ac3": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "lo3": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "hi3": unicorn.mips_const.UC_MIPS_REG_INVALID,
            }
        )


class MIPSBEMachineDef(MIPSMachineDef):
    """Unicorn machine definition for mips32 big-endian"""

    byteorder = Byteorder.BIG

    uc_mode = unicorn.UC_MODE_MIPS32 | unicorn.UC_MODE_BIG_ENDIAN

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # *** Accumulator Registers ***
                # TODO: Unicorn broke support for these in 2.0.2
                "ac0": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "hi0": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "lo0": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "ac1": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "hi1": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "lo1": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "ac2": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "hi2": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "lo2": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "ac3": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "hi3": unicorn.mips_const.UC_MIPS_REG_INVALID,
                "lo3": unicorn.mips_const.UC_MIPS_REG_INVALID,
            }
        )
