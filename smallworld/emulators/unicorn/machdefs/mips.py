import capstone
import unicorn

from ....platforms import Architecture, Byteorder
from .machdef import UnicornMachineDef


class MIPSMachineDef(UnicornMachineDef):
    """Unicorn machine definition for mips32"""

    arch = Architecture.MIPS32

    uc_arch = unicorn.UC_ARCH_MIPS
    uc_mode = unicorn.UC_MODE_MIPS32

    cs_arch = capstone.CS_ARCH_MIPS
    cs_mode = capstone.CS_MODE_MIPS32

    pc_reg = "pc"

    def __init__(self):
        self._registers = {
            # *** General-Purpose Registers ***
            # Assembler Temporary Register
            "at": (unicorn.mips_const.UC_MIPS_REG_AT, "at", 0, 4),
            "1": (unicorn.mips_const.UC_MIPS_REG_1, "at", 0, 4),
            # Return Value Registers
            "v0": (unicorn.mips_const.UC_MIPS_REG_V0, "v0", 0, 4),
            "2": (unicorn.mips_const.UC_MIPS_REG_2, "v0", 0, 4),
            "v1": (unicorn.mips_const.UC_MIPS_REG_V1, "v1", 0, 4),
            "3": (unicorn.mips_const.UC_MIPS_REG_3, "v1", 0, 4),
            # Argument Registers
            "a0": (unicorn.mips_const.UC_MIPS_REG_A0, "a0", 0, 4),
            "4": (unicorn.mips_const.UC_MIPS_REG_4, "a0", 0, 4),
            "a1": (unicorn.mips_const.UC_MIPS_REG_A1, "a1", 0, 4),
            "5": (unicorn.mips_const.UC_MIPS_REG_5, "a1", 0, 4),
            "a2": (unicorn.mips_const.UC_MIPS_REG_A2, "a2", 0, 4),
            "6": (unicorn.mips_const.UC_MIPS_REG_6, "a2", 0, 4),
            "a3": (unicorn.mips_const.UC_MIPS_REG_A3, "a3", 0, 4),
            "7": (unicorn.mips_const.UC_MIPS_REG_7, "a3", 0, 4),
            # Temporary Registers
            "t0": (unicorn.mips_const.UC_MIPS_REG_T0, "t0", 0, 4),
            "8": (unicorn.mips_const.UC_MIPS_REG_8, "t0", 0, 4),
            "t1": (unicorn.mips_const.UC_MIPS_REG_T1, "t1", 0, 4),
            "9": (unicorn.mips_const.UC_MIPS_REG_9, "t1", 0, 4),
            "t2": (unicorn.mips_const.UC_MIPS_REG_T2, "t2", 0, 4),
            "10": (unicorn.mips_const.UC_MIPS_REG_10, "t2", 0, 4),
            "t3": (unicorn.mips_const.UC_MIPS_REG_T3, "t3", 0, 4),
            "11": (unicorn.mips_const.UC_MIPS_REG_11, "t3", 0, 4),
            "t4": (unicorn.mips_const.UC_MIPS_REG_T4, "t4", 0, 4),
            "12": (unicorn.mips_const.UC_MIPS_REG_12, "t4", 0, 4),
            "t5": (unicorn.mips_const.UC_MIPS_REG_T5, "t5", 0, 4),
            "13": (unicorn.mips_const.UC_MIPS_REG_13, "t5", 0, 4),
            "t6": (unicorn.mips_const.UC_MIPS_REG_T6, "t6", 0, 4),
            "14": (unicorn.mips_const.UC_MIPS_REG_14, "t6", 0, 4),
            "t7": (unicorn.mips_const.UC_MIPS_REG_T7, "t7", 0, 4),
            "15": (unicorn.mips_const.UC_MIPS_REG_15, "t7", 0, 4),
            "t8": (unicorn.mips_const.UC_MIPS_REG_T8, "t8", 0, 4),
            "24": (unicorn.mips_const.UC_MIPS_REG_24, "t8", 0, 4),
            "t9": (unicorn.mips_const.UC_MIPS_REG_T9, "t9", 0, 4),
            "25": (unicorn.mips_const.UC_MIPS_REG_25, "t9", 0, 4),
            # Saved Registers
            "s0": (unicorn.mips_const.UC_MIPS_REG_S0, "s0", 0, 4),
            "16": (unicorn.mips_const.UC_MIPS_REG_16, "s0", 0, 4),
            "s1": (unicorn.mips_const.UC_MIPS_REG_S1, "s1", 0, 4),
            "17": (unicorn.mips_const.UC_MIPS_REG_17, "s1", 0, 4),
            "s2": (unicorn.mips_const.UC_MIPS_REG_S2, "s2", 0, 4),
            "18": (unicorn.mips_const.UC_MIPS_REG_18, "s2", 0, 4),
            "s3": (unicorn.mips_const.UC_MIPS_REG_S3, "s3", 0, 4),
            "19": (unicorn.mips_const.UC_MIPS_REG_19, "s3", 0, 4),
            "s4": (unicorn.mips_const.UC_MIPS_REG_S4, "s4", 0, 4),
            "20": (unicorn.mips_const.UC_MIPS_REG_20, "s4", 0, 4),
            "s5": (unicorn.mips_const.UC_MIPS_REG_S5, "s5", 0, 4),
            "21": (unicorn.mips_const.UC_MIPS_REG_21, "s5", 0, 4),
            "s6": (unicorn.mips_const.UC_MIPS_REG_S6, "s6", 0, 4),
            "22": (unicorn.mips_const.UC_MIPS_REG_22, "s6", 0, 4),
            "s7": (unicorn.mips_const.UC_MIPS_REG_S7, "s7", 0, 4),
            "23": (unicorn.mips_const.UC_MIPS_REG_23, "s7", 0, 4),
            # NOTE: Register 30 used to be FP, is now also s8
            "s8": (unicorn.mips_const.UC_MIPS_REG_S8, "s8", 0, 4),
            "fp": (unicorn.mips_const.UC_MIPS_REG_FP, "s8", 0, 4),
            "30": (unicorn.mips_const.UC_MIPS_REG_30, "s8", 0, 4),
            # Kernel-reserved registers
            "k0": (unicorn.mips_const.UC_MIPS_REG_K0, "k0", 0, 4),
            "26": (unicorn.mips_const.UC_MIPS_REG_26, "k0", 0, 4),
            "k1": (unicorn.mips_const.UC_MIPS_REG_K1, "k1", 0, 4),
            "27": (unicorn.mips_const.UC_MIPS_REG_27, "k1", 0, 4),
            # *** Pointer Registers ***
            # Zero Register
            "zero": (unicorn.mips_const.UC_MIPS_REG_ZERO, "zero", 0, 4),
            "0": (unicorn.mips_const.UC_MIPS_REG_0, "zero", 0, 4),
            # Global Pointer Register
            "gp": (unicorn.mips_const.UC_MIPS_REG_GP, "gp", 0, 4),
            "28": (unicorn.mips_const.UC_MIPS_REG_28, "gp", 0, 4),
            # Stack Pointer Register
            "sp": (unicorn.mips_const.UC_MIPS_REG_SP, "sp", 0, 4),
            "29": (unicorn.mips_const.UC_MIPS_REG_29, "sp", 0, 4),
            # Return Address Register
            "ra": (unicorn.mips_const.UC_MIPS_REG_RA, "ra", 0, 4),
            "31": (unicorn.mips_const.UC_MIPS_REG_31, "ra", 0, 4),
            # Program Counter
            "pc": (unicorn.mips_const.UC_MIPS_REG_PC, "pc", 0, 4),
            # *** Floating-point Registers ***
            "f0": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f0", 0, 4),
            "f1": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f1", 0, 4),
            "f2": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f2", 0, 4),
            "f3": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f3", 0, 4),
            "f4": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f4", 0, 4),
            "f5": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f5", 0, 4),
            "f6": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f6", 0, 4),
            "f7": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f7", 0, 4),
            "f8": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f8", 0, 4),
            "f9": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f9", 0, 4),
            "f10": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f10", 0, 4),
            "f11": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f11", 0, 4),
            "f12": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f12", 0, 4),
            "f13": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f13", 0, 4),
            "f14": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f14", 0, 4),
            "f15": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f15", 0, 4),
            "f16": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f16", 0, 4),
            "f17": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f17", 0, 4),
            "f18": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f18", 0, 4),
            "f19": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f19", 0, 4),
            "f20": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f20", 0, 4),
            "f21": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f21", 0, 4),
            "f22": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f22", 0, 4),
            "f23": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f23", 0, 4),
            "f24": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f24", 0, 4),
            "f25": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f25", 0, 4),
            "f26": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f26", 0, 4),
            "f27": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f27", 0, 4),
            "f28": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f28", 0, 4),
            "f29": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f29", 0, 4),
            "f30": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f30", 0, 4),
            "f31": (unicorn.mips_const.UC_MIPS_REG_INVALID, "f31", 0, 4),
            # *** Floating Point Control Registers ***
            # NOTE: These are taken from Sleigh, and the MIPS docs.
            # Unicorn doesn't use these names, and has a different number of registers.
            "fir": (unicorn.mips_const.UC_MIPS_REG_INVALID, "fir", 0, 4),
            "fcsr": (unicorn.mips_const.UC_MIPS_REG_INVALID, "fcsr", 0, 4),
            "fexr": (unicorn.mips_const.UC_MIPS_REG_INVALID, "fexr", 0, 4),
            "fenr": (unicorn.mips_const.UC_MIPS_REG_INVALID, "fenr", 0, 4),
            "fccr": (unicorn.mips_const.UC_MIPS_REG_INVALID, "fccr", 0, 4),
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
                "ac0": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac0", 0, 8),
                "lo0": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac0", 0, 4),
                "hi0": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac0", 4, 4),
                "ac1": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac1", 0, 8),
                "lo1": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac1", 0, 4),
                "hi1": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac1", 4, 4),
                "ac2": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac2", 0, 8),
                "lo2": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac2", 0, 4),
                "hi2": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac2", 4, 4),
                "ac3": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac3", 0, 8),
                "lo3": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac3", 0, 4),
                "hi3": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac3", 4, 4),
            }
        )


class MIPSBEMachineDef(MIPSMachineDef):
    """Unicorn machine definition for mips32 big-endian"""

    byteorder = Byteorder.BIG

    uc_mode = unicorn.UC_MODE_MIPS32 | unicorn.UC_MODE_BIG_ENDIAN

    cs_mode = capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # *** Accumulator Registers ***
                # TODO: Unicorn broke support for these in 2.0.2
                "ac0": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac0", 0, 8),
                "hi0": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac0", 0, 4),
                "lo0": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac0", 4, 4),
                "ac1": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac1", 0, 8),
                "hi1": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac1", 0, 4),
                "lo1": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac1", 4, 4),
                "ac2": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac2", 0, 8),
                "hi2": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac2", 0, 4),
                "lo2": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac2", 4, 4),
                "ac3": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac3", 0, 8),
                "hi3": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac3", 0, 4),
                "lo3": (unicorn.mips_const.UC_MIPS_REG_INVALID, "ac3", 4, 4),
            }
        )
