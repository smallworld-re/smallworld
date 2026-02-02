import enum
import logging

import unicorn

from ....exceptions import EmulationExecExceptionFailure
from ....platforms import Architecture, Byteorder
from .machdef import UnicornMachineDef

logger = logging.getLogger(__name__)

# From unicorn/qemu/mips/cpu.h
# Descriptions from unicorn/qemu/mips/helpers.c


class MipsExcp(enum.IntEnum):
    EXCP_NONE = (-1,)  # No exception.  Wut?
    EXCP_RESET = 0  # Hard reset
    EXCP_SRESET = 1  # Soft reset
    EXCP_DSS = 2  # Debug single-step
    EXCP_DINT = 3  # Debug interrupt
    EXCP_DDBL = 4  # Debug data break load
    EXCP_DDBS = 5  # Debug data break store
    EXCP_NMI = 6  # Non-maskable interrupt
    EXCP_MCHECK = 7  # Machine check exception
    EXCP_EXT_INTERRUPT = 8  # External interrupt
    EXCP_DFWATCH = 9  # Deferred watchpoint
    EXCP_DIB = 10  # Debug instruction breakpoint
    EXCP_IWATCH = 11  # Instruction fetch watchpoint
    EXCP_AdEL = 12  # Address exception on load
    EXCP_AdES = 13  # Address exception on store
    EXCP_TLBF = 14  # TLB refill
    EXCP_IBE = 15  # Instruction bus error
    EXCP_DBp = 16  # Debug breakpoint
    EXCP_SYSCALL = 17  # Syscall instruction
    EXCP_BREAK = 18  # Break instruction
    EXCP_CpU = 19  # Coprocessor unusable
    EXCP_RI = 20  # Reserved instruction
    EXCP_OVERFLOW = 21  # Arithmetic overflow
    EXCP_TRAP = 22  # Trap instruction eval'd to true
    EXCP_FPE = 23  # Floating-point error
    EXCP_DWATCH = 24  # Data watchpoint
    EXCP_LTLBL = 25  # TLB write to unwritable page
    EXCP_TLBL = 26  # TLB load failed
    EXCP_TLBS = 27  # TLB store failed
    EXCP_DBE = 28  # Data bus error
    EXCP_THREAD = 29  # Thread yield
    EXCP_MDMX = 30  # MDMX vector processor exceptioon
    EXCP_C2E = 31  # Precise coprocessor 2 error
    EXCP_CACHE = 32  # Cache error
    EXCP_DSPDIS = 33  # DSP extensions disabled
    EXCP_MSADIS = 34  # MSA extensions disabled
    EXCP_MSAFPE = 35  # MSA floating point error
    EXCP_TLBXI = 36  # Tried to fetch from execute-protected memory
    EXCP_TLBRI = 37  # Tried to read from read-protected memory


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

    def handle_interrupt(self, intno: int, pc: int) -> None:
        # Unicorn treats all MIPS exceptions as interrupts,
        # including the ones that would normally raise UcError.
        #
        # Pending a fix to Unicorn, do the translation manually.
        if intno == MipsExcp.EXCP_MCHECK:
            # Machine check exception.
            # Uh oh.
            logger.error("Machine fault")
            raise EmulationExecExceptionFailure("MIPS machine fault", pc)

        elif intno in (
            MipsExcp.EXCP_DSS,
            MipsExcp.EXCP_DINT,
            MipsExcp.EXCP_DDBL,
            MipsExcp.EXCP_DDBS,
            MipsExcp.EXCP_DIB,
            MipsExcp.EXCP_DBp,
        ):
            # Debug exceptions.
            # If you are messing with this subsystem,
            # SmallWorld can't help you.
            logger.error(f"Debug exception: {MipsExcp(intno).name}")
            raise EmulationExecExceptionFailure("MIPS debug exception", pc)

        elif intno in (
            MipsExcp.EXCP_DFWATCH,
            MipsExcp.EXCP_IWATCH,
            MipsExcp.EXCP_DWATCH,
        ):
            # Watchpoint error.
            # If you are messing with this subsystem,
            # SmallWorld can't help you
            logger.error(f"Watchpoint exception: {MipsExcp(intno).name}")
            raise EmulationExecExceptionFailure("MIPS watchpoint exception", pc)

        elif intno == MipsExcp.EXCP_THREAD:
            # Thread yield exception.
            # If you are messing with this subsystem,
            # SmallWorld can't help you
            logger.error("Thread yield exception")
            raise EmulationExecExceptionFailure("MIPS thread yield exception", pc)

        elif intno in (MipsExcp.EXCP_RESET, MipsExcp.EXCP_SRESET):
            # Reset exception.
            # We really should never see this.
            logger.error(f"Reset signal: {MipsExcp(intno).name}")
            raise EmulationExecExceptionFailure("MIPS reset signal", pc)

        elif intno in (
            MipsExcp.EXCP_CpU,
            MipsExcp.EXCP_DSPDIS,
            MipsExcp.EXCP_MSADIS,
        ):
            # Coprocessor unavailable.
            # Raise as an illegal instruction error
            logger.debug(f"Coprocessor unavailable: {MipsExcp(intno).name}")
            raise unicorn.UcError(unicorn.UC_ERR_INSN_INVALID)

        elif intno in (MipsExcp.EXCP_NMI, MipsExcp.EXCP_EXT_INTERRUPT):
            # Interrupt of some kind.
            # TODO: Actually allow hooking for this?
            logger.error(f"External interrupt: {MipsExcp(intno).name}")
            raise EmulationExecExceptionFailure("MIPS external interrupt", pc)

        elif intno == MipsExcp.EXCP_RI:
            # Reserved instruction error.
            # Raise as an illegal instruction error
            logger.debug("Reserved instruction")
            raise unicorn.UcError(unicorn.UC_ERR_INSN_INVALID)

        elif intno == MipsExcp.EXCP_TLBL:
            # TLB load failure
            # Raise as a read unmappd
            # This can also cover a fetch, but it's hard to tell
            logger.debug("TLB load failure")
            raise unicorn.UcError(unicorn.UC_ERR_READ_UNMAPPED)

        elif intno == MipsExcp.EXCP_TLBS:
            # TLB store failure
            # Raise as a write unmapped
            logger.debug("TLB store failure")
            raise unicorn.UcError(unicorn.UC_ERR_WRITE_UNMAPPED)

        elif intno == MipsExcp.EXCP_TLBF:
            # TLB refill error
            # Annoyingly, this could be either a read or a write;
            # Unicorn doesn't give us that info.
            logger.error("TLB refill exception")
            logger.error("Not enough info from Unicorn to give an accurate cause")
            raise EmulationExecExceptionFailure("MIPS TLB refill exception", pc)

        elif intno == MipsExcp.EXCP_AdEL:
            # Address load error
            # Raise as an unaligned read
            # Could also be an unaligned fetch, but it's hard to tell
            logger.debug("Address load error")
            raise unicorn.UcError(unicorn.UC_ERR_READ_UNALIGNED)

        elif intno == MipsExcp.EXCP_AdES:
            # Address store error
            # Raise as an unaligned write
            logger.debug("Address store error")
            raise unicorn.UcError(unicorn.UC_ERR_WRITE_UNALIGNED)

        elif intno == MipsExcp.EXCP_LTLBL:
            # TLB modify error
            # I think this should get raised as a write protected error
            logger.debug("TLB modify error")
            raise unicorn.UcError(unicorn.UC_ERR_WRITE_PROT)

        elif intno == MipsExcp.EXCP_TLBXI:
            # TLB execute inhibited
            # Raise as a fetch protected error
            logger.debug("TLB execute-inhibit")
            raise unicorn.UcError(unicorn.UC_ERR_FETCH_PROT)

        elif intno == MipsExcp.EXCP_TLBRI:
            # TLB read inhibited
            # Raise as a read protected error
            logger.debug("TLB read-inhibit")
            raise unicorn.UcError(unicorn.UC_ERR_READ_PROT)

        elif intno == MipsExcp.EXCP_IBE:
            # Instruction bus error
            # Raise as a fetch unmapped; not quite right, but maybe?
            logger.debug("Instruction bus error")
            raise unicorn.UcError(unicorn.UC_ERR_FETCH_UNMAPPED)

        elif intno == MipsExcp.EXCP_DBE:
            # Data bus error
            # Annoyingly, this could be a read or a write.
            logger.error("Data bus error")
            logger.error("Not enough info from Unicorn to give an accurate cause")
            raise EmulationExecExceptionFailure("MIPS data bus error", pc)

        elif intno == MipsExcp.EXCP_CACHE:
            # Cache error.
            # No idea what this means, and it looks like it's not plumbed into QEMU...?
            logger.error("Cache error")
            logger.error(
                "At the time of writing, this doesn't look supported by QEMU/Unicorn...?"
            )
            raise EmulationExecExceptionFailure("MIPS cache error", pc)

        elif intno in (
            MipsExcp.EXCP_BREAK,
            MipsExcp.EXCP_TRAP,
            MipsExcp.EXCP_OVERFLOW,
            MipsExcp.EXCP_FPE,
            MipsExcp.EXCP_C2E,
            MipsExcp.EXCP_MDMX,
            MipsExcp.EXCP_MSAFPE,
        ):
            # Instruction or coprocessor errors
            # Treat as an illegal instruction.
            logger.error(f"Instruction failure: {MipsExcp(intno).name}")
            raise unicorn.UcError(unicorn.UC_ERR_INSN_INVALID)

        elif intno == MipsExcp.EXCP_SYSCALL:
            # System call instruction.
            # Treat as an illegal instruction
            # TODO: actually handle this.
            logger.error("System call")
            logger.error("UnicornEmulator currently doesn't support hooking these.")
            raise unicorn.UcError(unicorn.UC_ERR_INSN_INVALID)

        else:
            logger.error("Unexpected MIPS exception number: {intno}")
            raise EmulationExecExceptionFailure(f"Unhandled exception {intno}", pc)


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
