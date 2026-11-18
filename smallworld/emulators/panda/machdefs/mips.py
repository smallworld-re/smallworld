import enum
import logging

from .... import exceptions
from ....platforms import Architecture, Byteorder
from .machdef import PandaMachineDef

logger = logging.getLogger(__name__)


class MipsExcp(enum.IntEnum):
    """QEMU MIPS exception indices (target/mips cpu.h).

    PANDA and Unicorn are both QEMU-derived and share this numbering; this is
    the same table used by emulators/unicorn/machdefs/mips.py. Only EXCP_IBE
    (an unmapped instruction fetch) has been observed reaching PANDA's exception
    callback in this tree -- read/write faults are caught earlier by the memory
    callbacks -- but the whole table is mapped so any exception that does
    surface here is classified rather than reported as a generic error.
    """

    EXCP_RESET = 0
    EXCP_SRESET = 1
    EXCP_DSS = 2
    EXCP_DINT = 3
    EXCP_DDBL = 4
    EXCP_DDBS = 5
    EXCP_NMI = 6
    EXCP_MCHECK = 7
    EXCP_EXT_INTERRUPT = 8
    EXCP_DFWATCH = 9
    EXCP_DIB = 10
    EXCP_IWATCH = 11
    EXCP_AdEL = 12
    EXCP_AdES = 13
    EXCP_TLBF = 14
    EXCP_IBE = 15
    EXCP_DBp = 16
    EXCP_SYSCALL = 17
    EXCP_BREAK = 18
    EXCP_CpU = 19
    EXCP_RI = 20
    EXCP_OVERFLOW = 21
    EXCP_TRAP = 22
    EXCP_FPE = 23
    EXCP_DWATCH = 24
    EXCP_LTLBL = 25
    EXCP_TLBL = 26
    EXCP_TLBS = 27
    EXCP_DBE = 28
    EXCP_THREAD = 29
    EXCP_MDMX = 30
    EXCP_C2E = 31
    EXCP_CACHE = 32
    EXCP_DSPDIS = 33
    EXCP_MSADIS = 34
    EXCP_MSAFPE = 35
    EXCP_TLBXI = 36
    EXCP_TLBRI = 37


class MIPSMachineDef(PandaMachineDef):
    arch = Architecture.MIPS32
    cpu = "M14K"

    def handle_interrupt(self, intno: int, pc: int) -> None:
        # Ported from the Unicorn MIPS machdef's handle_interrupt table. Unicorn
        # re-raises a UcError that its _error() remaps into a smallworld
        # exception; PANDA has no such layer, so raise the exception directly.
        try:
            excp = MipsExcp(intno)
        except ValueError:
            super().handle_interrupt(intno, pc)
            return

        if excp == MipsExcp.EXCP_IBE:
            # Instruction bus error: an unmapped instruction fetch.
            raise exceptions.EmulationFetchUnmappedFailure(
                f"Fetched unmapped memory at {hex(pc)}", pc, address=pc
            )
        elif excp == MipsExcp.EXCP_TLBL:
            # TLB load failure -> read of unmapped memory.
            raise exceptions.EmulationReadUnmappedFailure(
                "MIPS TLB load failure", pc, address=pc
            )
        elif excp == MipsExcp.EXCP_TLBS:
            # TLB store failure -> write to unmapped memory.
            raise exceptions.EmulationWriteUnmappedFailure(
                "MIPS TLB store failure", pc, address=pc
            )
        elif excp == MipsExcp.EXCP_TLBRI:
            # TLB read inhibited -> read of read-protected memory.
            raise exceptions.EmulationReadProtectedFailure(
                "MIPS TLB read-inhibit", pc, address=pc
            )
        elif excp == MipsExcp.EXCP_LTLBL:
            # TLB modify on an unwritable page -> write-protected memory.
            raise exceptions.EmulationWriteProtectedFailure(
                "MIPS TLB modify error", pc, address=pc
            )
        elif excp == MipsExcp.EXCP_TLBXI:
            # TLB execute inhibited -> fetch from exec-protected memory.
            raise exceptions.EmulationFetchProtectedFailure(
                "MIPS TLB execute-inhibit", pc, address=pc
            )
        elif excp == MipsExcp.EXCP_AdEL:
            # Address error on load -> unaligned read.
            raise exceptions.EmulationReadUnalignedFailure(
                "MIPS address load error", pc, address=pc
            )
        elif excp == MipsExcp.EXCP_AdES:
            # Address error on store -> unaligned write.
            raise exceptions.EmulationWriteUnalignedFailure(
                "MIPS address store error", pc, address=pc
            )
        elif excp in (
            MipsExcp.EXCP_CpU,
            MipsExcp.EXCP_DSPDIS,
            MipsExcp.EXCP_MSADIS,
            MipsExcp.EXCP_RI,
            MipsExcp.EXCP_BREAK,
            MipsExcp.EXCP_TRAP,
            MipsExcp.EXCP_OVERFLOW,
            MipsExcp.EXCP_FPE,
            MipsExcp.EXCP_C2E,
            MipsExcp.EXCP_MDMX,
            MipsExcp.EXCP_MSAFPE,
            MipsExcp.EXCP_SYSCALL,
        ):
            # Reserved/illegal instructions, coprocessor faults, and traps.
            logger.debug(f"MIPS instruction fault: {excp.name}")
            raise exceptions.EmulationExecInvalidFailure(
                f"MIPS instruction fault ({excp.name})", pc, None
            )
        elif excp in (
            MipsExcp.EXCP_TLBF,
            MipsExcp.EXCP_DBE,
            MipsExcp.EXCP_CACHE,
            MipsExcp.EXCP_MCHECK,
        ):
            # Memory faults QEMU cannot resolve to read vs write, plus machine
            # and cache checks: report a generic execution exception.
            logger.error(f"MIPS unresolved fault: {excp.name}")
            raise exceptions.EmulationExecExceptionFailure(f"MIPS {excp.name}", pc)
        elif excp in (
            MipsExcp.EXCP_DSS,
            MipsExcp.EXCP_DINT,
            MipsExcp.EXCP_DDBL,
            MipsExcp.EXCP_DDBS,
            MipsExcp.EXCP_DIB,
            MipsExcp.EXCP_DBp,
            MipsExcp.EXCP_DFWATCH,
            MipsExcp.EXCP_IWATCH,
            MipsExcp.EXCP_DWATCH,
            MipsExcp.EXCP_THREAD,
            MipsExcp.EXCP_RESET,
            MipsExcp.EXCP_SRESET,
            MipsExcp.EXCP_NMI,
            MipsExcp.EXCP_EXT_INTERRUPT,
        ):
            # Debug/watchpoint/reset/interrupt/thread events smallworld does not
            # model: surface as an execution exception.
            logger.error(f"MIPS system exception: {excp.name}")
            raise exceptions.EmulationExecExceptionFailure(f"MIPS {excp.name}", pc)

        # Defensive: an enum member with no explicit branch above.
        super().handle_interrupt(intno, pc)

    # I'm going to define all the ones we are making possible as of now
    # I need to submit a PR to change to X86 32 bit and to includ eflags
    def __init__(self):
        self._registers = {
            "at": "at",
            "1": "at",
            "v0": "v0",
            "2": "v0",
            "v1": "v1",
            "3": "v1",
            "a0": "a0",
            "4": "a0",
            "a1": "a1",
            "5": "a1",
            "a2": "a2",
            "6": "a2",
            "a3": "a3",
            "7": "a3",
            "t0": "t0",
            "8": "t0",
            "t1": "t1",
            "9": "t1",
            "t2": "t2",
            "10": "t2",
            "t3": "t3",
            "11": "t3",
            "t4": "t4",
            "12": "t4",
            "t5": "t5",
            "13": "t5",
            "t6": "t6",
            "14": "t6",
            "t7": "t7",
            "15": "t7",
            "t8": "t8",
            "24": "t8",
            "t9": "t9",
            "25": "t9",
            "s0": "s0",
            "16": "s0",
            "s1": "s1",
            "17": "s1",
            "s2": "s2",
            "18": "s2",
            "s3": "s3",
            "19": "s3",
            "s4": "s4",
            "20": "s4",
            "s5": "s5",
            "21": "s5",
            "s6": "s6",
            "22": "s6",
            "s7": "s7",
            "23": "s7",
            "s8": "fp",
            "fp": "fp",
            "30": "fp",
            "k0": "k0",
            "26": "k0",
            "k1": "k1",
            "27": "k1",
            "zero": "zero",
            "0": "zero",
            "gp": "gp",
            "28": "gp",
            "sp": "sp",
            "29": "sp",
            "ra": "ra",
            "31": "ra",
            "pc": "pc",
            "f0": None,
            "f1": None,
            "f2": None,
            "f3": None,
            "f4": None,
            "f5": None,
            "f6": None,
            "f7": None,
            "f8": None,
            "f9": None,
            "f10": None,
            "f11": None,
            "f12": None,
            "f13": None,
            "f14": None,
            "f15": None,
            "f16": None,
            "f17": None,
            "f18": None,
            "f19": None,
            "f20": None,
            "f21": None,
            "f22": None,
            "f23": None,
            "f24": None,
            "f25": None,
            "f26": None,
            "f27": None,
            "f28": None,
            "f29": None,
            "f30": None,
            "f31": None,
            "fir": None,
            "fcsr": None,
            "fexr": None,
            "fenr": None,
            "fccr": None,
            "ac0": None,
            "lo0": None,
            "hi0": None,
            "ac1": None,
            "lo1": None,
            "hi1": None,
            "ac2": None,
            "lo2": None,
            "hi2": None,
            "ac3": None,
            "lo3": None,
            "hi3": None,
        }


class MIPSELMachineDef(MIPSMachineDef):
    panda_arch = "mipsel"
    byteorder = Byteorder.LITTLE


class MIPSBEMachineDef(MIPSMachineDef):
    panda_arch = "mips"
    byteorder = Byteorder.BIG
