import capstone

from ..platforms import Architecture, Byteorder
from .platformdef import PlatformDef, RegisterAliasDef, RegisterDef


class M68K(PlatformDef):
    architecture = Architecture.M68K
    byteorder = Byteorder.BIG

    address_size = 4

    capstone_arch = capstone.CS_ARCH_M68K
    capstone_mode = capstone.CS_MODE_BIG_ENDIAN
    # NOTE: m68k is a very loose family of processors
    # There's a lot of evolution between the variants.

    # NOTE: m68k is technically a Harvard architecture.
    #
    # The memory bus protocol encodes the kind of access
    # being performed into each memory operation,
    # split between user code, user data, supervisor code
    # and supervisor data.
    # In theory, this can allow the memory controller
    # to give each category of data its own address space.
    # It can also be used to extend the address space
    # from 32-bit to 35-bit.
    #
    # For now, SmallWorld is assuming this feature isn't really used.

    conditional_branch_mnemonics = {
        # Conditional branches
        "bcc",
        "bcs",
        "beq",
        "bge",
        "bgt",
        "bhi",
        "ble",
        "bls",
        "blt",
        "bmi",
        "bne",
        "bpl",
        "bvc",
        "bvs",
        # Decrement and Conditional Branch
        "dbcc",
        "dbcs",
        "dbeq",
        "dbge",
        "dbgt",
        "dbhi",
        "dble",
        "dbls",
        "dblt",
        "dbmi",
        "dbne",
        "dbpl",
        "dbvc",
        "dbvs",
    }

    compare_mnemonics = {
        "cmpb",
        "cmpw",
        "cmpl",
        "tstb",
        "tstw",
        "tstl",
    }

    pc_register = "pc"
    sp_register = "usp"

    # Special registers:
    # - usp: User stack pointer
    # - isp: Interrupt stack pointer
    # - msp: Master stack pointer
    # - sr: Status Register
    # - vbr: Interrupt vector base register
    # - dfc: Destination function code register (used in addressing)
    # - sfc: Source function code register (used in addressing)
    #
    # The data registers "dX" and the address registers "aX"
    # can be used in slightly different sets of operations,
    # but they're general enough to be considered GPRs
    general_purpose_registers = [
        "d0",
        "d1",
        "d2",
        "d3",
        "d4",
        "d5",
        "d6",
        "d7",
        "a0",
        "a1",
        "a2",
        "a3",
        "a4",
        "a5",
        "a6",
    ]

    registers = {
        # Data registers
        "d0": RegisterDef(name="d0", size=4),
        "d1": RegisterDef(name="d1", size=4),
        "d2": RegisterDef(name="d2", size=4),
        "d3": RegisterDef(name="d3", size=4),
        "d4": RegisterDef(name="d4", size=4),
        "d5": RegisterDef(name="d5", size=4),
        "d6": RegisterDef(name="d6", size=4),
        "d7": RegisterDef(name="d7", size=4),
        # Address registers
        "a0": RegisterDef(name="a0", size=4),
        "a1": RegisterDef(name="a1", size=4),
        "a2": RegisterDef(name="a2", size=4),
        "a3": RegisterDef(name="a3", size=4),
        "a4": RegisterDef(name="a4", size=4),
        "a5": RegisterDef(name="a5", size=4),
        # a6 is used as the frame pointer in Linux calling conventions.
        "a6": RegisterDef(name="a6", size=4),
        "fp": RegisterAliasDef(name="fp", parent="a6", size=4, offset=0),
        # a7 is the stack pointer.
        # It is aliased to "sp" in many disassemblers
        #
        # a7 is actually an alias for one of three registers,
        # depending on system mode:
        #
        # - usp; the User Stack Pointer
        # - isp; the Interrupt Stack Pointer (called Supervisor Stack Pointer on M68010 and earlier)
        # - msp; the Master Stack Pointer (M68020 and later)
        #
        # SmallWorld's machine state assumes that a7 is aliased to usp.
        "usp": RegisterDef(name="usp", size=4),
        "a7": RegisterAliasDef(name="a7", parent="usp", size=4, offset=0),
        "sp": RegisterAliasDef(name="sp", parent="usp", size=4, offset=0),
        # Program Counter
        "pc": RegisterDef(name="pc", size=4),
        # Floating-point control register
        "fpcr": RegisterDef(name="fpcr", size=4),
        # Floating-point status register
        "fpsr": RegisterDef(name="fpsr", size=4),
        # Floating-point instruction address register
        "fpiar": RegisterDef(name="fpiar", size=4),
        # Floating-point registers.
        # NOTE: These use the same 80-bit format as x87
        "fp0": RegisterDef(name="fp0", size=10),
        "fp1": RegisterDef(name="fp1", size=10),
        "fp2": RegisterDef(name="fp2", size=10),
        "fp3": RegisterDef(name="fp3", size=10),
        "fp4": RegisterDef(name="fp4", size=10),
        "fp5": RegisterDef(name="fp5", size=10),
        "fp6": RegisterDef(name="fp6", size=10),
        "fp7": RegisterDef(name="fp7", size=10),
        # NOTE: Everything past this point is privileged state
        # Interrupt stack pointer
        # Also called the Supervisor stack pointer in earlier versions
        "isp": RegisterDef(name="isp", size=4),
        "ssp": RegisterAliasDef(name="ssp", parent="isp", size=4, offset=0),
        # Master stack pointer
        "msp": RegisterDef(name="msp", size=4),
        # Status register
        # Include condition code register as a one-byte alias
        "sr": RegisterDef(name="sr", size=2),
        "ccr": RegisterAliasDef(name="ccr", parent="sr", size=1, offset=0),
        # Interrupt vector base register
        "vbr": RegisterDef(name="vbr", size=4),
        # Function code registers
        "sfc": RegisterDef(name="sfc", size=1),
        "dfc": RegisterDef(name="dfc", size=1),
        # Cache control register
        "cacr": RegisterDef(name="cacr", size=4),
        # User root pointer register
        "urp": RegisterDef(name="urp", size=4),
        # Supervisor root pointer register
        "srp": RegisterDef(name="srp", size=4),
        # Translation control register
        "tc": RegisterDef(name="tc", size=2),
        # Data transparent translation registers
        "dtt0": RegisterDef(name="dtt0", size=4),
        "dtt1": RegisterDef(name="dtt1", size=4),
        # Instruction transparent translationr registers
        "itt0": RegisterDef(name="itt0", size=4),
        "itt1": RegisterDef(name="itt1", size=4),
        # MMU status register
        "mmusr": RegisterDef(name="mmusr", size=4),
    }
