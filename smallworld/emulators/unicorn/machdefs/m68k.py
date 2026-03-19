import enum
import logging

import unicorn

from ....exceptions import EmulationExecExceptionFailure
from ....platforms import Architecture, Byteorder
from .machdef import UnicornMachineDef

logger = logging.getLogger(__name__)


class M68KExcp(enum.IntEnum):
    # NOTE: Exceptions 0 and 1 are reserved for a reset exception.
    # Unlike other architectures, these numbers correspond directly
    # to the interrupt vector index.
    # The Reset exception needs two addresses to do its thing,
    # while the rest of the exceptions just need a single slot.
    EXCP_ACCESS = 2  # Access (MMU) error
    EXCP_ADDRESS = 3  # Address alignment error
    EXCP_ILLEGAL = 4  # Illegal instruction
    EXCP_DIV0 = 5  # Divide by zero
    EXCP_CHK = 6  # Raised by CHK, CHK2 instructions
    EXCP_TRAPCC = 7  # Raised by FTRAPcc, TRAPcc, TRAPV instructions
    EXCP_PRIVILEGE = 8  # Privilege violation
    EXCP_TRACE = 9  # Single-step tracepoint trap
    EXCP_LINEA = 10  # Unimplemented line-A opcode (usually mapped to MAC coprocessor)
    EXCP_LINEF = 11  # Unimplemented line-F opcode (usually mapped to FPU coprocessor)
    EXCP_DEBUGNBP = 12  # Non-breakpoint debug interrupt
    EXCP_DEBUGBP = 13  # Breakpoint debug interrupt
    EXCP_FORMAT = 14  # Invalid stack on execution of RTE (exception return)
    EXCP_UNINITIALIZED = 15  # Interrupt for which specific vector is uninitialized
    EXCP_SPURIOUS = 16  # Someone interrupted, but didn't own up when we asked who
    EXCP_INT_0 = 24  # Interrupt level 0 autovector
    EXCP_INT_1 = 25  # Interrupt level 1 autovector
    EXCP_INT_2 = 26  # Interrupt level 2 autovector
    EXCP_INT_3 = 27  # Interrupt level 3 autovector
    EXCP_INT_4 = 28  # Interrupt level 4 autovector
    EXCP_INT_5 = 29  # Interrupt level 5 autovector
    EXCP_INT_6 = 30  # Interrupt level 6 autovector
    EXCP_INT_7 = 31  # Interrupt level 7 autovector
    EXCP_TRAP0 = 32  # Trap instruction 0
    EXCP_TRAP1 = 33  # Trap instruction 1
    EXCP_TRAP2 = 34  # Trap instruction 2
    EXCP_TRAP3 = 35  # Trap instruction 3
    EXCP_TRAP4 = 36  # Trap instruction 4
    EXCP_TRAP5 = 37  # Trap instruction 5
    EXCP_TRAP6 = 38  # Trap instruction 6
    EXCP_TRAP7 = 39  # Trap instruction 7
    EXCP_TRAP8 = 40  # Trap instruction 8
    EXCP_TRAP9 = 41  # Trap instruction 9
    EXCP_TRAPA = 42  # Trap instruction 10
    EXCP_TRAPB = 43  # Trap instruction 11
    EXCP_TRAPC = 44  # Trap instruction 12
    EXCP_TRAPD = 45  # Trap instruction 13
    EXCP_TRAPE = 46  # Trap instruction 14
    EXCP_TRAPF = 47  # Trap instruction 15
    EXCP_FP_BSUN = 48  # FPU Branch set on Unordered
    EXCP_FP_INEX = 49  # FPU inexact result
    EXCP_FP_DZ = 50  # FPU divide by zero
    EXCP_FP_UNFL = 51  # FPU underflow
    EXCP_FP_OPERR = 52  # FPU operand error
    EXCP_FP_OVFL = 53  # FPU overflow
    EXCP_FP_SNAN = 54  # FPU signalling NaN encountered
    EXCP_FP_UNIMP = 55  # FPU unimplemented data type
    EXCP_MMU_CONF = 56  # MMU coniguration error
    EXCP_MMU_ILLEGAL = 57  # MMU illegal operation error
    EXCP_MMU_ACCESS = 58  # MMU access level violation
    EXCP_RTE = 0x100  # Indicates RTE; I suspect it's a QEMU internalism
    EXCP_HALT_INSN = 0x101  # Indicates HALT; I suspect it's a QEMU internalism


class M68KMachineDef(UnicornMachineDef):
    arch = Architecture.M68K
    byteorder = Byteorder.BIG

    uc_arch = unicorn.UC_ARCH_M68K
    uc_mode = unicorn.UC_MODE_BIG_ENDIAN
    uc_cpu = unicorn.m68k_const.UC_CPU_M68K_M68040

    _registers = {
        # Data registers
        "d0": unicorn.m68k_const.UC_M68K_REG_D0,
        "d1": unicorn.m68k_const.UC_M68K_REG_D1,
        "d2": unicorn.m68k_const.UC_M68K_REG_D2,
        "d3": unicorn.m68k_const.UC_M68K_REG_D3,
        "d4": unicorn.m68k_const.UC_M68K_REG_D4,
        "d5": unicorn.m68k_const.UC_M68K_REG_D5,
        "d6": unicorn.m68k_const.UC_M68K_REG_D6,
        "d7": unicorn.m68k_const.UC_M68K_REG_D7,
        # Address registers
        "a0": unicorn.m68k_const.UC_M68K_REG_A0,
        "a1": unicorn.m68k_const.UC_M68K_REG_A1,
        "a2": unicorn.m68k_const.UC_M68K_REG_A2,
        "a3": unicorn.m68k_const.UC_M68K_REG_A3,
        "a4": unicorn.m68k_const.UC_M68K_REG_A4,
        "a5": unicorn.m68k_const.UC_M68K_REG_A5,
        "a6": unicorn.m68k_const.UC_M68K_REG_A6,
        "fp": unicorn.m68k_const.UC_M68K_REG_A6,
        # User stack pointer
        "usp": unicorn.m68k_const.UC_M68K_REG_A7,
        "sp": unicorn.m68k_const.UC_M68K_REG_A7,
        "a7": unicorn.m68k_const.UC_M68K_REG_A7,
        # Program counter
        "pc": unicorn.m68k_const.UC_M68K_REG_PC,
        # Floating-point control register
        "fpcr": unicorn.m68k_const.UC_M68K_REG_INVALID,
        # Floating-point status register
        "fpsr": unicorn.m68k_const.UC_M68K_REG_INVALID,
        # Floating-point instruction address register
        "fpiar": unicorn.m68k_const.UC_M68K_REG_INVALID,
        # Floating-point registers
        "fp0": unicorn.m68k_const.UC_M68K_REG_INVALID,
        "fp1": unicorn.m68k_const.UC_M68K_REG_INVALID,
        "fp2": unicorn.m68k_const.UC_M68K_REG_INVALID,
        "fp3": unicorn.m68k_const.UC_M68K_REG_INVALID,
        "fp4": unicorn.m68k_const.UC_M68K_REG_INVALID,
        "fp5": unicorn.m68k_const.UC_M68K_REG_INVALID,
        "fp6": unicorn.m68k_const.UC_M68K_REG_INVALID,
        "fp7": unicorn.m68k_const.UC_M68K_REG_INVALID,
        # NOTE: Everything past this point is privileged state
        "isp": unicorn.m68k_const.UC_M68K_REG_CR_ISP,
        "ssp": unicorn.m68k_const.UC_M68K_REG_CR_ISP,
        "msp": unicorn.m68k_const.UC_M68K_REG_CR_MSP,
        "sr": unicorn.m68k_const.UC_M68K_REG_SR,
        "ccr": unicorn.m68k_const.UC_M68K_REG_SR,
        # NOTE: vbr access is deprecated in Unicorn
        "vbr": unicorn.m68k_const.UC_M68K_REG_INVALID,
        "sfc": unicorn.m68k_const.UC_M68K_REG_CR_SFC,
        "dfc": unicorn.m68k_const.UC_M68K_REG_CR_DFC,
        "cacr": unicorn.m68k_const.UC_M68K_REG_CR_CACR,
        "urp": unicorn.m68k_const.UC_M68K_REG_CR_URP,
        "srp": unicorn.m68k_const.UC_M68K_REG_CR_SRP,
        "tc": unicorn.m68k_const.UC_M68K_REG_CR_TC,
        "dtt0": unicorn.m68k_const.UC_M68K_REG_CR_DTT0,
        "dtt1": unicorn.m68k_const.UC_M68K_REG_CR_DTT1,
        "itt0": unicorn.m68k_const.UC_M68K_REG_CR_ITT0,
        "itt1": unicorn.m68k_const.UC_M68K_REG_CR_ITT1,
        "mmusr": unicorn.m68k_const.UC_M68K_REG_CR_MMUSR,
    }

    def handle_interrupt(self, intno: int, pc: int) -> None:
        if intno == M68KExcp.EXCP_ACCESS:
            # Memory access error
            # Sadly, I don't know what kind of access this is,
            # or if it's an unmapped or prot error
            logger.debug("Memory access error")
            raise unicorn.UcError(unicorn.UC_ERR_READ_UNMAPPED)
        elif intno == M68KExcp.EXCP_ADDRESS:
            # Address alignment error
            # Sadly, I don't know what kind of access caused this.
            logger.debug("Address alignment error")
            raise unicorn.UcError(unicorn.UC_ERR_READ_UNALIGNED)
        elif intno in (
            M68KExcp.EXCP_ILLEGAL,
            M68KExcp.EXCP_DIV0,
            M68KExcp.EXCP_CHK,
            M68KExcp.EXCP_TRAPCC,
            M68KExcp.EXCP_PRIVILEGE,
            M68KExcp.EXCP_LINEA,
            M68KExcp.EXCP_LINEF,
        ):
            # Illegal instructions or various kinds of instruction traps
            # Treat as an illegal instruction
            logger.debug(f"Instruction fault: {M68KExcp(intno).name}")
            raise unicorn.UcError(unicorn.UC_ERR_INSN_INVALID)
        elif intno in (
            M68KExcp.EXCP_DEBUGNBP,
            M68KExcp.EXCP_DEBUGBP,
        ):
            # Debug exception.
            # If you are messing with this subsystem,
            # SmallWorld can't help you.
            logger.error(f"Debug exception: {M68KExcp(intno).name}")
            raise EmulationExecExceptionFailure("M68K debug exception", pc)
        elif intno == M68KExcp.EXCP_FORMAT:
            # Invalid stack layout for RTE.
            # Treat as an illegal instruction
            logger.debug("Invalid exception stack")
            raise EmulationExecExceptionFailure("Invalid exception stack", pc)
        elif intno == M68KExcp.EXCP_SPURIOUS:
            # Spurious interrupt; no idea who sent it.
            logger.error("'Spurious' hardware interrupt")
            raise EmulationExecExceptionFailure("'Spurious' hardware interrupt", pc)
        elif intno in (
            M68KExcp.EXCP_INT_0,
            M68KExcp.EXCP_INT_1,
            M68KExcp.EXCP_INT_2,
            M68KExcp.EXCP_INT_3,
            M68KExcp.EXCP_INT_4,
            M68KExcp.EXCP_INT_5,
            M68KExcp.EXCP_INT_6,
            M68KExcp.EXCP_INT_7,
        ):
            # Hardware interrupt
            # TODO: Actually allow hooking for this?
            level = intno - M68KExcp.EXCP_INT_0
            logger.error(f"External interrupt level {level}")
            raise EmulationExecExceptionFailure(
                "M68K External interrupt level {level}", pc
            )

        elif intno in (
            M68KExcp.EXCP_TRAP0,
            M68KExcp.EXCP_TRAP1,
            M68KExcp.EXCP_TRAP2,
            M68KExcp.EXCP_TRAP3,
            M68KExcp.EXCP_TRAP4,
            M68KExcp.EXCP_TRAP5,
            M68KExcp.EXCP_TRAP6,
            M68KExcp.EXCP_TRAP7,
            M68KExcp.EXCP_TRAP8,
            M68KExcp.EXCP_TRAP9,
            M68KExcp.EXCP_TRAPA,
            M68KExcp.EXCP_TRAPB,
            M68KExcp.EXCP_TRAPC,
            M68KExcp.EXCP_TRAPD,
            M68KExcp.EXCP_TRAPE,
            M68KExcp.EXCP_TRAPF,
        ):
            # Trap instructiom
            # Treat as illegal instruction
            code = intno - M68KExcp.EXCP_TRAP0
            logger.debug(f"Trap instruction, code {code}")
            raise unicorn.UcError(unicorn.UC_ERR_INSN_INVALID)

        elif intno in (
            M68KExcp.EXCP_FP_BSUN,
            M68KExcp.EXCP_FP_INEX,
            M68KExcp.EXCP_FP_DZ,
            M68KExcp.EXCP_FP_UNFL,
            M68KExcp.EXCP_FP_OPERR,
            M68KExcp.EXCP_FP_OVFL,
            M68KExcp.EXCP_FP_SNAN,
            M68KExcp.EXCP_FP_UNIMP,
        ):
            # Floating-point error.
            # Treat as illegal instruction
            logger.debug(f"Floating point error {M68KExcp(intno).name}")
            raise unicorn.UcError(unicorn.UC_ERR_INSN_INVALID)

        elif intno in (
            M68KExcp.EXCP_MMU_CONF,
            M68KExcp.EXCP_MMU_ILLEGAL,
            M68KExcp.EXCP_MMU_ACCESS,
        ):
            # MMU error
            # Treat as illegal instruction fault?
            logger.debug(f"MMU error {M68KExcp(intno).name}")
            raise unicorn.UcError(unicorn.UC_ERR_INSN_INVALID)
        elif intno in (M68KExcp.EXCP_RTE, M68KExcp.EXCP_HALT_INSN):
            # I don't think these are real exceptions.
            logger.error(
                f"Sketchy m68k exception; is this real, or a QEMUism: {M68KExcp(intno).name}"
            )
            raise EmulationExecExceptionFailure(
                "Sketchy M68K exception: {M68KExcp(intno).name}", pc
            )

        else:
            # M68K defines a lot more trap numbers (0x0 - 0x3ff)
            # Some of these are allowed to be user-defined,
            # so theoretically it's possible for a system to raise them
            logger.error(f"Unknown m68k exception: {intno}")
            raise EmulationExecExceptionFailure("Unknown M68K exception: {intno}", pc)
