import typing

from ....platforms import Architecture, Byteorder
from ....platforms.defs.superh4 import (
    SH4_PROGRAM_COUNTER_REGISTER,
    SH4_REGISTER_ALIASES,
    SH4_STATUS_REGISTER,
)
from .machdef import GhidraMachineDef

# Ghidra's SuperH4 sleigh spec is inconsistent about case: general-purpose and
# floating-point registers are lowercase (`r0`, `fr0`, `dr0`, `xf0`, `xd0`), but
# the banked, control and system registers are uppercase. Everything not listed
# here keeps its SmallWorld spelling.
#
# `GhidraMachineDef.pcode_reg` asserts the looked-up name resolves, so a case
# slip is a hard AssertionError rather than a graceful UnsupportedRegisterError.
SH4_GHIDRA_NAMES = {
    SH4_PROGRAM_COUNTER_REGISTER: "PC",
    SH4_STATUS_REGISTER: "SR",
    "pr": "PR",
    "gbr": "GBR",
    "vbr": "VBR",
    "ssr": "SSR",
    "spc": "SPC",
    "sgr": "SGR",
    "dbr": "DBR",
    "mach": "MACH",
    "macl": "MACL",
    "fpscr": "FPSCR",
    "fpul": "FPUL",
    **{f"r{i}_bank": f"R{i}_BANK" for i in range(0, 8)},
}


class SuperH4MachineDef(GhidraMachineDef):
    """Shared SH-4/SH-4A definition.

    Has no ``byteorder`` or ``language_id``, so ``find_subclass`` never selects
    it; the concrete subclasses below do.
    """

    arch = Architecture.SUPERH_SH4

    # As on SH-2A: sleigh folds the delay slot into the owning branch.
    supports_single_step = True

    _registers: typing.Dict[str, typing.Optional[str]] = {
        # *** General-Purpose Registers ***
        **{f"r{i}": f"r{i}" for i in range(0, 16)},
        # Sleigh has no `sp`/`fp`/`ra`/`lr`; resolve each alias to the Ghidra
        # spelling of the register it names (`ra`/`lr` land on PR).
        **{
            alias: SH4_GHIDRA_NAMES.get(parent, parent)
            for alias, parent in SH4_REGISTER_ALIASES.items()
        },
        # *** Banked, Control and System Registers ***
        **SH4_GHIDRA_NAMES,
        # *** Floating-Point Registers ***
        # Two banks: fr/dr is the active one, xf/xd the alternate, swapped by
        # `frchg`. This name map is endian-independent for the primary bank, but
        # not for the alternate one, and only half of that is Ghidra being
        # consistent: its little-endian spec swaps the names of each fr pair so
        # that DRn = FRn:FRn+1 holds in both endiannesses, yet leaves the xf
        # names unswapped, so in `SuperH4:LE:32:default` xf{n} is the *low* half
        # of xd{n}. SmallWorld's platform definition models the architectural
        # layout for both banks, so `SuperH4ELMachineDef` below transposes the xf
        # pairs back - see `platforms.defs.superh.float_bank_registers`.
        **{f"dr{i}": f"dr{i}" for i in range(0, 16, 2)},
        **{f"fr{i}": f"fr{i}" for i in range(0, 16)},
        **{f"xd{i}": f"xd{i}" for i in range(0, 16, 2)},
        **{f"xf{i}": f"xf{i}" for i in range(0, 16)},
        # NOTE: the sleigh spec also defines the vector registers
        # fv0/fv4/fv8/fv12 and the SR/FPSCR bit fields (T, S, M, Q, IMASK, MD,
        # RB, BL, FD, FPSCR_*). None are in the platform definition, so there is
        # nothing to map for them. That is not free on SH-4, where T/S/M/Q and
        # FPSCR_PR are the registers the semantics actually read: sleigh only
        # refreshes them from SR/FPSCR inside `ldc Rm,SR` / `lds Rm,FPSCR`, so a
        # harness that writes `sr` or `fpscr` directly is silently ignored by
        # every pcode-derived backend (SH-2A is unaffected - its spec uses
        # `sr[0,1]` for T directly).
    }


class SuperH4BEMachineDef(SuperH4MachineDef):
    byteorder = Byteorder.BIG
    language_id = "SuperH4:BE:32:default"


class SuperH4ELMachineDef(SuperH4MachineDef):
    byteorder = Byteorder.LITTLE
    language_id = "SuperH4:LE:32:default"

    # Undo sleigh's unswapped alternate-bank names; see the note on
    # `_registers` above. Measured on `SuperH4:LE:32:default`: xd0 sits at
    # register-space offset 0x240 size 8, xf0 at 0x240 size 4, xf1 at 0x244, so
    # sleigh's xf0 is the low half of xd0 while SmallWorld's is the high half.
    # Left as-is, every xf read and write on little-endian SH-4 would silently
    # name the opposite half from the platform definition, the CPU state model
    # and PANDA.
    _registers = {
        **SuperH4MachineDef._registers,
        **{f"xf{i}": f"xf{i + 1}" for i in range(0, 16, 2)},
        **{f"xf{i + 1}": f"xf{i}" for i in range(0, 16, 2)},
    }
