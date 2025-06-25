from ..platforms import Architecture, Byteorder
from .platformdef import PlatformDef, RegisterAliasDef, RegisterDef

# NOTE: Xtensa is designed to be an extensible language
# There are options for Xtensa chips to implement almost any
# ISA feature you can bally well think of,
# some of which are closed-source and closed-spec.
#
# Support for any specific extension depends on the emulator.


class Xtensa(PlatformDef):
    architecture = Architecture.XTENSA
    byteorder = Byteorder.LITTLE

    address_size = 4

    conditional_branch_mnemonics = {
        # Compare to zero and branch
        "beqz",
        "bnez",
        "bgez",
        "bltz",
        # Compare to immediate and branch
        "beqi",
        "bnei",
        "bgei",
        "blti",
        # Compare to unsigned immediate and branch
        "bgeui",
        "bltui",
        # Compare to register and branch
        "beq",
        "bne",
        "bge",
        "blt",
        # Compare to unsigned register and branch
        "bgeu",
        "bltu",
        # Bit test versus immediate and branch
        "bbci",
        "bbsi",
        # Bit test versus register and branch
        "bbc",
        "bbs",
        # Test against bitmask and branch
        "bany",
        "bnone",
        "ball",
        "bnall",
    }

    # Xtensa core has no comparison operations;
    # they're built into the branch instructions.
    compare_mnemonics = set()

    # NOTE: Capstone does not yet support xtensa
    # It looks like it's either planned, or present in a newer version than we use.
    capstone_arch = -1
    capstone_mode = -1

    pc_register = "pc"

    # Special registers:
    # - a0 is the default link register
    # - a1 is the stack pointer
    general_purpose_registers = [f"a{i}" for i in range(2, 16)]

    registers = {
        # *** General Purpose Registers ***
        # a0 is also the default link register, but it doesn't get an alias
        "a0": RegisterDef(name="a0", size=4),
        # a1 is also the stack pointer
        "a1": RegisterDef(name="a1", size=4),
        "sp": RegisterAliasDef(name="sp", parent="a1", size=4, offset=0),
        "a2": RegisterDef(name="a2", size=4),
        "a3": RegisterDef(name="a3", size=4),
        "a4": RegisterDef(name="a4", size=4),
        "a5": RegisterDef(name="a5", size=4),
        "a6": RegisterDef(name="a6", size=4),
        "a7": RegisterDef(name="a7", size=4),
        "a8": RegisterDef(name="a8", size=4),
        "a9": RegisterDef(name="a9", size=4),
        "a10": RegisterDef(name="a10", size=4),
        "a11": RegisterDef(name="a11", size=4),
        "a12": RegisterDef(name="a12", size=4),
        "a13": RegisterDef(name="a13", size=4),
        "a14": RegisterDef(name="a14", size=4),
        "a15": RegisterDef(name="a15", size=4),
        # *** Program Counter ***
        "pc": RegisterDef(name="pc", size=4),
        # *** Shift Amount Register ***
        # This thing is actually 6 bits.
        "sar": RegisterDef(name="sar", size=4),
    }
