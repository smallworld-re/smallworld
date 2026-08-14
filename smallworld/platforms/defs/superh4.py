import typing

import capstone

from ..platforms import Architecture, Byteorder
from .platformdef import PlatformDef, RegisterAliasDef, RegisterDef
from .superh import SH2A_DELAY_SLOT_MNEMONICS, float_bank_registers

SH4_PROGRAM_COUNTER_REGISTER = "pc"
SH4_STATUS_REGISTER = "sr"
SH4_STACK_POINTER_ALIAS = "sp"
SH4_STACK_POINTER_REGISTER = "r15"
SH4_FRAME_POINTER_ALIAS = "fp"
SH4_FRAME_POINTER_REGISTER = "r14"
SH4_RETURN_ADDRESS_ALIAS = "ra"
SH4_LINK_REGISTER_ALIAS = "lr"
SH4_RETURN_ADDRESS_REGISTER = "pr"
SH4_RETURN_VALUE_REGISTER = "r0"
SH4_FLOAT_RETURN_VALUE_REGISTER = "fr0"
SH4_INTEGER_ARGUMENT_REGISTERS = ("r4", "r5", "r6", "r7")
# SH-4's cspec passes eight single-precision arguments, versus SH-2A's four.
SH4_FLOAT_ARGUMENT_REGISTERS = (
    "fr4",
    "fr5",
    "fr6",
    "fr7",
    "fr8",
    "fr9",
    "fr10",
    "fr11",
)
SH4_DOUBLE_ARGUMENT_REGISTERS = ("dr4", "dr6", "dr8", "dr10")

# Same rationale as the SH-2A aliases: `pr` is where `bsr`/`jsr` leave the
# return address, and naming it `ra` lets SH-4 reuse the `"ra"` branch of
# `state.models.model.Model.get_return_address`.
SH4_REGISTER_ALIASES = {
    SH4_STACK_POINTER_ALIAS: SH4_STACK_POINTER_REGISTER,
    SH4_FRAME_POINTER_ALIAS: SH4_FRAME_POINTER_REGISTER,
    SH4_RETURN_ADDRESS_ALIAS: SH4_RETURN_ADDRESS_REGISTER,
    SH4_LINK_REGISTER_ALIAS: SH4_RETURN_ADDRESS_REGISTER,
}


class SuperH4Def(PlatformDef):
    """Shared SH-4/SH-4A definition; see :class:`SuperH4BE` and :class:`SuperH4EL`.

    Ghidra models SH-4 with a single language per endianness
    (``SuperH4:{BE,LE}:32:default``), compiled from a spec whose header says it
    "defines SuperH version 4a, but should work against versions 1, 2, and 3".
    So one SmallWorld architecture covers SH-4 and SH-4A, and the capstone mode
    below asks for the SH-4A superset.
    """

    architecture = Architecture.SUPERH_SH4

    address_size = 4

    capstone_arch = capstone.CS_ARCH_SH

    conditional_branch_mnemonics = {
        "bf",
        "bf/s",
        "bt",
        "bt/s",
    }

    compare_mnemonics = {
        "cmp/eq",
        "cmp/ge",
        "cmp/gt",
        "cmp/hi",
        "cmp/hs",
        "cmp/pl",
        "cmp/pz",
        "cmp/str",
        "fcmp/eq",
        "fcmp/gt",
        "tst",
    }

    # SH-4 has no `/n` forms, so every control transfer takes a delay slot.
    delay_slot_mnemonics = SH2A_DELAY_SLOT_MNEMONICS

    implicit_dereference_mnemonics = {
        "jmp",
        "jsr",
    }

    pc_register = SH4_PROGRAM_COUNTER_REGISTER
    sp_register = SH4_STACK_POINTER_ALIAS

    # r15 (sp) is excluded for the same reason as on SH-2A.
    general_purpose_registers = [f"r{i}" for i in range(0, 15)]

    registers: typing.Dict[str, RegisterDef] = {
        # *** General-Purpose Registers ***
        **{f"r{i}": RegisterDef(name=f"r{i}", size=4) for i in range(0, 16)},
        **{
            alias: RegisterAliasDef(name=alias, parent=parent, size=4, offset=0)
            for alias, parent in SH4_REGISTER_ALIASES.items()
        },
        # *** Banked Registers ***
        # SH-4 keeps a second copy of r0-r7, selected by SR.RB. Ghidra models
        # the inactive bank as R0_BANK-R7_BANK.
        **{f"r{i}_bank": RegisterDef(name=f"r{i}_bank", size=4) for i in range(0, 8)},
        # *** Control Registers ***
        SH4_PROGRAM_COUNTER_REGISTER: RegisterDef(
            name=SH4_PROGRAM_COUNTER_REGISTER, size=4
        ),
        SH4_STATUS_REGISTER: RegisterDef(name=SH4_STATUS_REGISTER, size=4),
        # Procedure register; holds the return address.
        "pr": RegisterDef(name="pr", size=4),
        "gbr": RegisterDef(name="gbr", size=4),
        "vbr": RegisterDef(name="vbr", size=4),
        # Saved status/PC/R15 and the debug base register. SH-4 only; SH-2A
        # has `tbr` here instead.
        "ssr": RegisterDef(name="ssr", size=4),
        "spc": RegisterDef(name="spc", size=4),
        "sgr": RegisterDef(name="sgr", size=4),
        "dbr": RegisterDef(name="dbr", size=4),
        # *** Multiply-Accumulate Registers ***
        "mach": RegisterDef(name="mach", size=4),
        "macl": RegisterDef(name="macl", size=4),
        # *** Floating-Point Registers ***
        # Two banks, swapped by `frchg`: fr/dr is the active one, xf/xd the
        # alternate.
        #
        # NOTE: Ghidra's little-endian SuperH4 spec swaps the names of each `fr`
        # pair but *not* each `xf` pair, so on `SuperH4:LE:32:default` sleigh
        # holds `xf{n}` in the low half of `xd{n}` while this (architectural)
        # model holds it in the high half. See `superh.float_bank_registers`.
        #
        # NOTE: Ghidra also defines the vector registers fv0/fv4/fv8/fv12
        # (16 bytes, overlaying dr) and xmtrx. They are only reachable via
        # `fipr`/`ftrv`, and SmallWorld's single-parent RegisterAliasDef
        # cannot express a three-level fv -> dr -> fr tree, so they are
        # deliberately not exposed.
        **float_bank_registers("dr", "fr"),
        **float_bank_registers("xd", "xf"),
        # *** Floating-Point Control Registers ***
        "fpscr": RegisterDef(name="fpscr", size=4),
        "fpul": RegisterDef(name="fpul", size=4),
    }


class SuperH4BE(SuperH4Def):
    byteorder = Byteorder.BIG

    capstone_mode = (
        capstone.CS_MODE_SH4A | capstone.CS_MODE_SHFPU | capstone.CS_MODE_BIG_ENDIAN
    )


class SuperH4EL(SuperH4Def):
    byteorder = Byteorder.LITTLE

    capstone_mode = capstone.CS_MODE_SH4A | capstone.CS_MODE_SHFPU
