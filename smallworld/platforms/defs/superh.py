import typing

import capstone

from ..platforms import Architecture, Byteorder
from .platformdef import PlatformDef, RegisterAliasDef, RegisterDef

SH2A_PROGRAM_COUNTER_REGISTER = "pc"
SH2A_STATUS_REGISTER = "sr"
SH2A_STACK_POINTER_ALIAS = "sp"
SH2A_STACK_POINTER_REGISTER = "r15"
SH2A_FRAME_POINTER_ALIAS = "fp"
SH2A_FRAME_POINTER_REGISTER = "r14"
SH2A_RETURN_ADDRESS_ALIAS = "ra"
SH2A_LINK_REGISTER_ALIAS = "lr"
SH2A_RETURN_ADDRESS_REGISTER = "pr"
SH2A_RETURN_VALUE_REGISTER = "r0"
SH2A_FLOAT_RETURN_VALUE_REGISTER = "fr0"
SH2A_INTEGER_ARGUMENT_REGISTERS = ("r4", "r5", "r6", "r7")
SH2A_FLOAT_ARGUMENT_REGISTERS = ("fr4", "fr5", "fr6", "fr7")

# SmallWorld uses `ra` and `lr` for the architectural PR register, which is where
# `bsr`/`jsr` deposit the return address and where `rts` jumps back to. Keeping
# the alias mapping centralized means every engine exposes the same ABI surface
# and return-register vocabulary, and it lets SH-2A reuse the `"ra"` branch of
# `state.models.model.Model.get_return_address` unchanged.
SH2A_REGISTER_ALIASES = {
    SH2A_STACK_POINTER_ALIAS: SH2A_STACK_POINTER_REGISTER,
    SH2A_FRAME_POINTER_ALIAS: SH2A_FRAME_POINTER_REGISTER,
    SH2A_RETURN_ADDRESS_ALIAS: SH2A_RETURN_ADDRESS_REGISTER,
    SH2A_LINK_REGISTER_ALIAS: SH2A_RETURN_ADDRESS_REGISTER,
}

# Every SuperH control transfer except the SH-2A `/n` forms executes the
# following instruction before taking effect.
SH2A_DELAY_SLOT_MNEMONICS = {
    "bra",
    "braf",
    "bsr",
    "bsrf",
    "jmp",
    "jsr",
    "rte",
    "rts",
    "bt/s",
    "bf/s",
}


def float_bank_registers(
    double_prefix: str, single_prefix: str
) -> typing.Dict[str, RegisterDef]:
    """Build one SuperH floating-point bank.

    The 8-byte double-precision register is the parent and the two
    single-precision registers are sub-registers of it.

    ``RegisterAliasDef.offset`` is a *numeric* offset - ``RegisterAlias`` masks
    with ``((1 << size*8) - 1) << offset*8`` and shifts right by ``offset*8`` -
    not a byte position. The SH architecture defines ``DRn = FRn:FRn+1`` with
    FRn as the upper half, so the even-numbered single-precision register sits
    at numeric offset 4 and the odd-numbered one at 0, in both endiannesses.

    NOTE: that architectural layout is what SmallWorld models, and it is what
    Ghidra's sleigh implements for the *primary* bank in both endiannesses -
    ``SuperH4.sinc``'s little-endian block swaps the names of each ``fr`` pair
    precisely to keep ``DRn = FRn:FRn+1`` fixed. It does not do the same for
    SH-4's alternate bank: the ``xf`` names are left unswapped, so on
    ``SuperH4:LE:32:default`` sleigh puts ``xf{n}`` in the *lower* half of
    ``xd{n}``. The little-endian angr and Ghidra machdefs therefore transpose
    the ``xf`` pairs back when mapping onto sleigh; Styx maps no ``xf`` at all.
    ``xd*`` is unaffected either way.
    """
    registers: typing.Dict[str, RegisterDef] = {}
    for i in range(0, 16, 2):
        double = f"{double_prefix}{i}"
        registers[double] = RegisterDef(name=double, size=8)
        registers[f"{single_prefix}{i}"] = RegisterAliasDef(
            name=f"{single_prefix}{i}", parent=double, size=4, offset=4
        )
        registers[f"{single_prefix}{i + 1}"] = RegisterAliasDef(
            name=f"{single_prefix}{i + 1}", parent=double, size=4, offset=0
        )
    return registers


class SH2AFPU(PlatformDef):
    """SH-2A-FPU, big-endian.

    Ghidra's only SH-2A language - ``SuperH:BE:32:SH-2A``, which is also the one
    pypcode and Styx bundle - is compiled from ``sh-2a.slaspec``, which sets
    ``@define FPU "1"``. So the only SH-2A model available to us is the
    FPU-equipped one, and it exists in big-endian form only; there is no
    ``SuperH:LE:32:SH-2A``.
    """

    architecture = Architecture.SUPERH_SH2A_FPU
    byteorder = Byteorder.BIG
    ghidra_language_id = "SuperH:BE:32:SH-2A"

    address_size = 4

    capstone_arch = capstone.CS_ARCH_SH
    capstone_mode = (
        capstone.CS_MODE_SH2A | capstone.CS_MODE_SHFPU | capstone.CS_MODE_BIG_ENDIAN
    )

    # SuperH has exactly two conditional branches, each with a delay-slot form.
    # Everything else branches on the T bit having already been set.
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

    # NOTE: the SH-2A `rts/n`, `rtv/n` and `jsr/n` forms exist precisely so that
    # a control transfer can *skip* its delay slot, so they are deliberately
    # absent here.
    delay_slot_mnemonics = SH2A_DELAY_SLOT_MNEMONICS

    implicit_dereference_mnemonics = {
        "jmp",
        "jsr",
        "jsr/n",
    }

    pc_register = SH2A_PROGRAM_COUNTER_REGISTER
    sp_register = SH2A_STACK_POINTER_ALIAS

    # r15 is the stack pointer per the SH ABI, so it is excluded: the colorizer
    # and trace-execution analyses write every general-purpose register, and
    # clobbering sp would break the harness rather than test it. r14 is only
    # conventionally a frame pointer, and MIPS includes its equivalent (s8), so
    # it stays.
    general_purpose_registers = [f"r{i}" for i in range(0, 15)]

    registers = {
        # *** General-Purpose Registers ***
        **{f"r{i}": RegisterDef(name=f"r{i}", size=4) for i in range(0, 16)},
        **{
            alias: RegisterAliasDef(name=alias, parent=parent, size=4, offset=0)
            for alias, parent in SH2A_REGISTER_ALIASES.items()
        },
        # *** Control Registers ***
        SH2A_PROGRAM_COUNTER_REGISTER: RegisterDef(
            name=SH2A_PROGRAM_COUNTER_REGISTER, size=4
        ),
        SH2A_STATUS_REGISTER: RegisterDef(name=SH2A_STATUS_REGISTER, size=4),
        # Procedure register; holds the return address.
        "pr": RegisterDef(name="pr", size=4),
        # Global and vector base registers.
        "gbr": RegisterDef(name="gbr", size=4),
        "vbr": RegisterDef(name="vbr", size=4),
        # Table base register; SH-2A only, backs `jsr/n @@(disp,tbr)`.
        "tbr": RegisterDef(name="tbr", size=4),
        # *** Multiply-Accumulate Registers ***
        "mach": RegisterDef(name="mach", size=4),
        "macl": RegisterDef(name="macl", size=4),
        # *** Floating-Point Registers ***
        # The sleigh spec defines fr0-fr15 (4 bytes) and dr0-dr14 (8 bytes) at
        # the same register-space offsets, so the double-precision registers are
        # the parents and the single-precision ones are sub-registers. See
        # `float_bank_registers` for the offset convention. SH-2A has a single
        # bank, unlike SH-4's fr/xf pair.
        **float_bank_registers("dr", "fr"),
        # *** Floating-Point Control Registers ***
        "fpscr": RegisterDef(name="fpscr", size=4),
        "fpul": RegisterDef(name="fpul", size=4),
    }
