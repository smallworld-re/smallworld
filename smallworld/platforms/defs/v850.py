from ..platforms import Architecture, Byteorder
from .platformdef import PlatformDef, RegisterAliasDef, RegisterDef

V850_PROGRAM_COUNTER_REGISTER = "pc"
V850_STATUS_REGISTER = "psw"
V850_STACK_POINTER_REGISTER = "sp"
V850_RETURN_ADDRESS_REGISTER = "lp"
V850_RETURN_VALUE_REGISTER = "r10"
V850_ARGUMENT_REGISTERS = ("r6", "r7", "r8", "r9")

# The V850 ABI names five of the general registers. Ghidra's language calls
# them by these names only, so SmallWorld does too, and keeps the numbered
# names as aliases.
V850_NAMED_REGISTERS = {
    "sp": "r3",
    "gp": "r4",
    "tp": "r5",
    "ep": "r30",
    "lp": "r31",
}

# The system registers that Ghidra's language models, except its placeholders
# for the debug registers (DBG22..DBG27). The fp* registers are V850E2M's FPU.
V850_SYSTEM_REGISTERS = (
    "eipc",
    "eipsw",
    "fepc",
    "fepsw",
    "ecr",
    V850_STATUS_REGISTER,
    "fpsr",
    "fpepc",
    "fpst",
    "fpcc",
    "fpcfg",
    "sccfg",
    "scbp",
    "eiic",
    "feic",
    "dbic",
    "ctpc",
    "ctpsw",
    "dbpc",
    "dbpsw",
    "ctbp",
    "dir",
    "eiwr",
    "fewr",
    "dbwr",
    "bsel",
)


_BY_NUMBER = {number: name for name, number in V850_NAMED_REGISTERS.items()}

#: r0 to r31, under the names Ghidra's language uses.
V850_GENERAL_REGISTERS = tuple(_BY_NUMBER.get(f"r{i}", f"r{i}") for i in range(32))


class V850(PlatformDef):
    """Renesas V850E1, V850E2 and V850E2M.

    Ghidra's V850 language covers these three cores, including V850E2M's
    FPU, in one language: it accepts every V850E2M instruction whichever core
    the code was written for. It does not model RH850 (V850E3v5). Most of
    RH850's additional instructions do not decode, but a few reuse encodings
    that V850 decodes as writes to r0 and run as those instead: `loop` as
    `mulhi`, `synci` as `mov`, and `ld.dw` and `st.dw` as `ld.bu`.
    """

    architecture = Architecture.V850
    byteorder = Byteorder.LITTLE
    ghidra_language_id = "V850:LE:32:default"

    address_size = 4

    # Capstone has no V850.
    capstone_arch = -1
    capstone_mode = -1

    conditional_branch_mnemonics = {
        # The names Ghidra's language uses...
        "bv",
        "bnv",
        "bc",
        "bnc",
        "be",
        "bne",
        "bnh",
        "bh",
        "bn",
        "bp",
        "bsa",
        "blt",
        "bge",
        "ble",
        "bgt",
        # ...and GNU's aliases for some of them.
        "bl",
        "bnl",
        "bz",
        "bnz",
    }

    compare_mnemonics = {"cmp", "tst", "tst1", "cmpf.s", "cmpf.d"}

    implicit_dereference_mnemonics = {"jmp"}

    pc_register = V850_PROGRAM_COUNTER_REGISTER
    sp_register = V850_STACK_POINTER_REGISTER
    status_register = V850_STATUS_REGISTER

    general_purpose_registers = [
        name for name in V850_GENERAL_REGISTERS if name not in ("r0", "sp")
    ]

    registers = {
        **{name: RegisterDef(name=name, size=4) for name in V850_GENERAL_REGISTERS},
        **{
            number: RegisterAliasDef(name=number, parent=name, size=4, offset=0)
            for name, number in V850_NAMED_REGISTERS.items()
        },
        V850_PROGRAM_COUNTER_REGISTER: RegisterDef(
            name=V850_PROGRAM_COUNTER_REGISTER, size=4
        ),
        **{name: RegisterDef(name=name, size=4) for name in V850_SYSTEM_REGISTERS},
    }
