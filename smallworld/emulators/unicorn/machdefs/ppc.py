import logging

import unicorn
import unicorn.ppc_const

from ....platforms import Architecture, Byteorder
from .machdef import UnicornMachineDef

logger = logging.getLogger(__name__)


class PPCMachineDef(UnicornMachineDef):
    """Unicorn machine definition for powerpc"""

    byteorder = Byteorder.BIG

    uc_arch = unicorn.UC_ARCH_PPC

    _registers = {
        "r0": unicorn.ppc_const.UC_PPC_REG_0,
        "r1": unicorn.ppc_const.UC_PPC_REG_1,
        "sp": unicorn.ppc_const.UC_PPC_REG_1,
        "r2": unicorn.ppc_const.UC_PPC_REG_2,
        "r3": unicorn.ppc_const.UC_PPC_REG_3,
        "r4": unicorn.ppc_const.UC_PPC_REG_4,
        "r5": unicorn.ppc_const.UC_PPC_REG_5,
        "r6": unicorn.ppc_const.UC_PPC_REG_6,
        "r7": unicorn.ppc_const.UC_PPC_REG_7,
        "r8": unicorn.ppc_const.UC_PPC_REG_8,
        "r9": unicorn.ppc_const.UC_PPC_REG_9,
        "r10": unicorn.ppc_const.UC_PPC_REG_10,
        "r11": unicorn.ppc_const.UC_PPC_REG_11,
        "r12": unicorn.ppc_const.UC_PPC_REG_12,
        "r13": unicorn.ppc_const.UC_PPC_REG_13,
        "r14": unicorn.ppc_const.UC_PPC_REG_14,
        "r15": unicorn.ppc_const.UC_PPC_REG_15,
        "r16": unicorn.ppc_const.UC_PPC_REG_16,
        "r17": unicorn.ppc_const.UC_PPC_REG_17,
        "r18": unicorn.ppc_const.UC_PPC_REG_18,
        "r19": unicorn.ppc_const.UC_PPC_REG_19,
        "r20": unicorn.ppc_const.UC_PPC_REG_20,
        "r21": unicorn.ppc_const.UC_PPC_REG_21,
        "r22": unicorn.ppc_const.UC_PPC_REG_22,
        "r23": unicorn.ppc_const.UC_PPC_REG_23,
        "r24": unicorn.ppc_const.UC_PPC_REG_24,
        "r25": unicorn.ppc_const.UC_PPC_REG_25,
        "r26": unicorn.ppc_const.UC_PPC_REG_26,
        "r27": unicorn.ppc_const.UC_PPC_REG_27,
        "r28": unicorn.ppc_const.UC_PPC_REG_28,
        "r29": unicorn.ppc_const.UC_PPC_REG_29,
        "r30": unicorn.ppc_const.UC_PPC_REG_30,
        "r31": unicorn.ppc_const.UC_PPC_REG_31,
        "bp": unicorn.ppc_const.UC_PPC_REG_31,
        "pc": unicorn.ppc_const.UC_PPC_REG_PC,
        "lr": unicorn.ppc_const.UC_PPC_REG_LR,
        "ctr": unicorn.ppc_const.UC_PPC_REG_CTR,
        "cr0": unicorn.ppc_const.UC_PPC_REG_CR0,
        "cr1": unicorn.ppc_const.UC_PPC_REG_CR1,
        "cr2": unicorn.ppc_const.UC_PPC_REG_CR2,
        "cr3": unicorn.ppc_const.UC_PPC_REG_CR3,
        "cr4": unicorn.ppc_const.UC_PPC_REG_CR4,
        "cr5": unicorn.ppc_const.UC_PPC_REG_CR5,
        "cr6": unicorn.ppc_const.UC_PPC_REG_CR6,
        "cr7": unicorn.ppc_const.UC_PPC_REG_CR7,
        "f0": unicorn.ppc_const.UC_PPC_REG_FPR0,
        "f1": unicorn.ppc_const.UC_PPC_REG_FPR1,
        "f2": unicorn.ppc_const.UC_PPC_REG_FPR2,
        "f3": unicorn.ppc_const.UC_PPC_REG_FPR3,
        "f4": unicorn.ppc_const.UC_PPC_REG_FPR4,
        "f5": unicorn.ppc_const.UC_PPC_REG_FPR5,
        "f6": unicorn.ppc_const.UC_PPC_REG_FPR6,
        "f7": unicorn.ppc_const.UC_PPC_REG_FPR7,
        "f8": unicorn.ppc_const.UC_PPC_REG_FPR8,
        "f9": unicorn.ppc_const.UC_PPC_REG_FPR9,
        "f10": unicorn.ppc_const.UC_PPC_REG_FPR10,
        "f11": unicorn.ppc_const.UC_PPC_REG_FPR11,
        "f12": unicorn.ppc_const.UC_PPC_REG_FPR12,
        "f13": unicorn.ppc_const.UC_PPC_REG_FPR13,
        "f14": unicorn.ppc_const.UC_PPC_REG_FPR14,
        "f15": unicorn.ppc_const.UC_PPC_REG_FPR15,
        "f16": unicorn.ppc_const.UC_PPC_REG_FPR16,
        "f17": unicorn.ppc_const.UC_PPC_REG_FPR17,
        "f18": unicorn.ppc_const.UC_PPC_REG_FPR18,
        "f19": unicorn.ppc_const.UC_PPC_REG_FPR19,
        "f20": unicorn.ppc_const.UC_PPC_REG_FPR20,
        "f21": unicorn.ppc_const.UC_PPC_REG_FPR21,
        "f22": unicorn.ppc_const.UC_PPC_REG_FPR22,
        "f23": unicorn.ppc_const.UC_PPC_REG_FPR23,
        "f24": unicorn.ppc_const.UC_PPC_REG_FPR24,
        "f25": unicorn.ppc_const.UC_PPC_REG_FPR25,
        "f26": unicorn.ppc_const.UC_PPC_REG_FPR26,
        "f27": unicorn.ppc_const.UC_PPC_REG_FPR27,
        "f28": unicorn.ppc_const.UC_PPC_REG_FPR28,
        "f29": unicorn.ppc_const.UC_PPC_REG_FPR29,
        "f30": unicorn.ppc_const.UC_PPC_REG_FPR30,
        "f31": unicorn.ppc_const.UC_PPC_REG_FPR31,
        "xer": unicorn.ppc_const.UC_PPC_REG_XER,
        "fpscr": unicorn.ppc_const.UC_PPC_REG_FPSCR,
    }


class PPC32MachineDef(PPCMachineDef):
    arch = Architecture.POWERPC32
    uc_mode = unicorn.UC_MODE_PPC32 | unicorn.UC_MODE_BIG_ENDIAN


class PPC64MachineDef(PPCMachineDef):
    arch = Architecture.POWERPC64
    uc_mode = unicorn.UC_MODE_PPC64 | unicorn.UC_MODE_BIG_ENDIAN

    def __init__(self, *args, **kwargs):
        logger.warning(
            "Unicorn PowerPC64 support is a work in progress.  This may not work."
        )
        super(*args, **kwargs)
