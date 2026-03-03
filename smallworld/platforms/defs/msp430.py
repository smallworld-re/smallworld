import typing

from ..platforms import Architecture, Byteorder
from .platformdef import PlatformDef, RegisterAliasDef, RegisterDef


class MSP430Def(PlatformDef):
    """Abstract platform definition for TI MSP430-series CPUs"""

    byteorder = Byteorder.LITTLE

    # Not supported by capstone
    capstone_arch = -1
    capstone_mode = -1

    conditional_branch_mnemonics = {
        "jeq",
        "jz",
        "jc",
        "jnc",
        "jn",
        "jge",
        "jl",
    }

    # This is another one where everything sets the flag bits,
    # so this list isn't exhaustive
    compare_mnemonics = {"cmp", "bit"}

    pc_register = "pc"
    sp_register = "sp"

    # - r0: Program counter
    # - r1: Stack pointer
    # - r2: Status register/constant generator 1
    # - r3: Constant generator 2
    #
    # Note: r2 is an alias for two registers
    # Whether it refers to SR or CG1 depends on the addressing mode
    # encoded in the instruction.
    #
    general_purpose_registers = [f"r{i}" for i in range(4, 16)]

    @property
    def registers(self) -> typing.Dict[str, RegisterDef]:
        return self._registers

    def __init__(self):
        self._registers = {
            # r0 is also the program counter.
            # I'm not sure it's actually possible to reference r0 directly...
            "pc": RegisterDef(name="pc", size=self.address_size),
            "r0": RegisterAliasDef(
                name="r0", parent="pc", size=self.address_size, offset=0
            ),
            # r1 is the system stack pointer
            "sp": RegisterDef(name="sp", size=self.address_size),
            "r1": RegisterAliasDef(
                name="r1", parent="sp", size=self.address_size, offset=0
            ),
            # r2 is actually two overlapping registers.
            # This model assumes you always want to access sr,
            # since the other option, cg1, is a bit useless to access; see below.
            "sr": RegisterDef(name="sr", size=self.address_size),
            "r2": RegisterAliasDef(
                name="r2", parent="sr", size=self.address_size, offset=0
            ),
            # msp430 has an interesting feature where
            # the values of r2 and r3 assume various values depending
            # on the addressing mode of the instruction in which they're used.
            "cg1": RegisterDef(name="cg1", size=self.address_size),
            # r3 is constant generator 2
            "cg2": RegisterDef(name="cg2", size=self.address_size),
            "r3": RegisterAliasDef(
                name="r3", parent="cg2", size=self.address_size, offset=0
            ),
            # General-purpose registers
            "r4": RegisterDef(name="r4", size=self.address_size),
            "r5": RegisterDef(name="r5", size=self.address_size),
            "r6": RegisterDef(name="r6", size=self.address_size),
            "r7": RegisterDef(name="r7", size=self.address_size),
            "r8": RegisterDef(name="r8", size=self.address_size),
            "r9": RegisterDef(name="r9", size=self.address_size),
            "r10": RegisterDef(name="r10", size=self.address_size),
            "r11": RegisterDef(name="r11", size=self.address_size),
            "r12": RegisterDef(name="r12", size=self.address_size),
            "r13": RegisterDef(name="r13", size=self.address_size),
            "r14": RegisterDef(name="r14", size=self.address_size),
            "r15": RegisterDef(name="r15", size=self.address_size),
        }


class MSP430(MSP430Def):
    """Platform definition for TI msp430 16-bit CPUs"""

    architecture = Architecture.MSP430
    address_size = 2


class MSP430X(MSP430Def):
    """Platform definition for TI msp430x 20-bit CPUs"""

    architecture = Architecture.MSP430X
    address_size = 4
