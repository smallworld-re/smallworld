import capstone

from ..platforms import Architecture, Byteorder
from .platformdef import PlatformDef, RegisterAliasDef, RegisterDef


class TriCore(PlatformDef):
    architecture = Architecture.TRICORE
    byteorder = Byteorder.LITTLE

    address_size = 4

    capstone_arch = capstone.CS_ARCH_TRICORE
    capstone_mode = capstone.CS_MODE_TRICORE_130

    conditional_branch_mnemonics = {
        "jge",
        "jgez",
        "jgtz",
        "jle",
        "jlez",
        "jlt",
        "jltz",
        "jne",
        "jnz",
        "jz",
    }

    compare_mnemonics = {
        "eq",
        "ge",
        "ge.u",
        "lt",
        "lt.u",
        "ne",
    }

    pc_register = "pc"
    sp_register = "sp"

    general_purpose_registers = [f"d{i}" for i in range(0, 16)] + [
        f"a{i}" for i in range(0, 10)
    ] + [f"a{i}" for i in range(12, 16)]

    registers = {
        **{f"d{i}": RegisterDef(name=f"d{i}", size=4) for i in range(0, 16)},
        **{f"a{i}": RegisterDef(name=f"a{i}", size=4) for i in range(0, 16)},
        "sp": RegisterAliasDef(name="sp", parent="a10", size=4, offset=0),
        "ra": RegisterAliasDef(name="ra", parent="a11", size=4, offset=0),
        "lr": RegisterAliasDef(name="lr", parent="a11", size=4, offset=0),
        "pc": RegisterDef(name="pc", size=4),
        "psw": RegisterDef(name="psw", size=4),
    }
