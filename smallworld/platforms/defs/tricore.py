import capstone

from ..platforms import Architecture, Byteorder
from .platformdef import PlatformDef, RegisterAliasDef, RegisterDef

TRICORE_PROGRAM_COUNTER_REGISTER = "pc"
TRICORE_STATUS_REGISTER = "psw"
TRICORE_STACK_POINTER_ALIAS = "sp"
TRICORE_STACK_POINTER_REGISTER = "a10"
TRICORE_RETURN_ADDRESS_ALIAS = "ra"
TRICORE_LINK_REGISTER_ALIAS = "lr"
TRICORE_RETURN_ADDRESS_REGISTER = "a11"
TRICORE_RETURN_VALUE_REGISTER = "d2"
TRICORE_INTEGER_ARGUMENT_REGISTERS = ("d4", "d5", "d6", "d7")
TRICORE_POINTER_ARGUMENT_REGISTERS = ("a4", "a5", "a6", "a7")

# SmallWorld uses both `ra` and `lr` names for the same architectural A11
# register. Keep the alias mapping centralized so every engine exposes the same
# ABI surface and return-register vocabulary.
TRICORE_REGISTER_ALIASES = {
    TRICORE_STACK_POINTER_ALIAS: TRICORE_STACK_POINTER_REGISTER,
    TRICORE_RETURN_ADDRESS_ALIAS: TRICORE_RETURN_ADDRESS_REGISTER,
    TRICORE_LINK_REGISTER_ALIAS: TRICORE_RETURN_ADDRESS_REGISTER,
}


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

    pc_register = TRICORE_PROGRAM_COUNTER_REGISTER
    sp_register = TRICORE_STACK_POINTER_ALIAS

    general_purpose_registers = (
        [f"d{i}" for i in range(0, 16)]
        + [f"a{i}" for i in range(0, 10)]
        + [f"a{i}" for i in range(12, 16)]
    )

    registers = {
        **{f"d{i}": RegisterDef(name=f"d{i}", size=4) for i in range(0, 16)},
        **{f"a{i}": RegisterDef(name=f"a{i}", size=4) for i in range(0, 16)},
        **{
            alias: RegisterAliasDef(name=alias, parent=parent, size=4, offset=0)
            for alias, parent in TRICORE_REGISTER_ALIASES.items()
        },
        TRICORE_PROGRAM_COUNTER_REGISTER: RegisterDef(
            name=TRICORE_PROGRAM_COUNTER_REGISTER, size=4
        ),
        TRICORE_STATUS_REGISTER: RegisterDef(name=TRICORE_STATUS_REGISTER, size=4),
    }
