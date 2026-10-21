import capstone

from ..platforms import Architecture, Byteorder
from .platformdef import PlatformDef, RegisterAliasDef, RegisterDef

# SPARC uses register windows: each `save` gives the callee a fresh set of
# %l and %i registers, with the caller's %o registers becoming the callee's
# %i registers, and `restore` undoes it.  The emulators keep the windows that
# are not current in incompatible ways -- Unicorn rotates a pointer over a
# fixed set of physical windows, while the Ghidra/angr p-code model copies
# the current window into a backing bank -- so this platform only names the
# 32 registers visible through the current window.  The windows belonging to
# callers are not part of the platform's register state.

SPARC_PROGRAM_COUNTER_REGISTER = "pc"
SPARC_NEXT_PROGRAM_COUNTER_REGISTER = "npc"
SPARC_STACK_POINTER_ALIAS = "sp"
SPARC_STACK_POINTER_REGISTER = "o6"
SPARC_FRAME_POINTER_ALIAS = "fp"
SPARC_FRAME_POINTER_REGISTER = "i6"
SPARC_RETURN_ADDRESS_REGISTER = "o7"
SPARC_MULTIPLY_STEP_REGISTER = "y"

# The window-visible integer registers, in architectural order r0-r31.
SPARC_WINDOW_REGISTERS = tuple(
    f"{group}{i}" for group in ("g", "o", "l", "i") for i in range(0, 8)
)

SPARC_REGISTER_ALIASES = {
    SPARC_STACK_POINTER_ALIAS: SPARC_STACK_POINTER_REGISTER,
    SPARC_FRAME_POINTER_ALIAS: SPARC_FRAME_POINTER_REGISTER,
}

# A `call` writes its own address to %o7, and the callee returns past the
# call and its delay slot, to %o7 + 8.
SPARC_RETURN_ADDRESS_OFFSET = 8

# Bicc and FBfcc condition names, in encoding order.  `ba`/`bn` and
# `fba`/`fbn` are unconditional.
_INTEGER_CONDITIONS = "n e le l leu cs neg vs a ne g ge gu cc pos vc".split()
_FLOAT_CONDITIONS = "n ne lg ul l ug g u a e ue ge uge le ule o".split()

_BRANCHES = [f"b{c}" for c in _INTEGER_CONDITIONS] + [
    f"fb{c}" for c in _FLOAT_CONDITIONS
]
_UNCONDITIONAL_BRANCHES = {"ba", "bn", "fba", "fbn"}


def _with_annul(mnemonics):
    # Capstone spells an annulled branch `bne,a`.
    return {m for base in mnemonics for m in (base, f"{base},a")}


class SPARC32(PlatformDef):
    """32-bit SPARC V8, user mode.

    Aimed at LEON-class processors.  Ghidra has no V8 language, so the
    p-code backends use its 32-bit V9 language, which decodes the V8
    privileged instructions (`rd %psr`, `wr %wim`, ...) as different V9
    instructions; only user-mode code runs the same on every backend.
    """

    architecture = Architecture.SPARC32
    byteorder = Byteorder.BIG
    ghidra_language_id = "sparc:BE:32:default"

    address_size = 4

    # Capstone's default SPARC mode is V8 (CS_MODE_V9 is the alternative).
    capstone_arch = capstone.CS_ARCH_SPARC
    capstone_mode = capstone.CS_MODE_BIG_ENDIAN

    conditional_branch_mnemonics = _with_annul(
        b for b in _BRANCHES if b not in _UNCONDITIONAL_BRANCHES
    )

    compare_mnemonics = {
        "cmp",
        "tst",
        "btst",
        "fcmps",
        "fcmpd",
        "fcmpq",
        "fcmpes",
        "fcmped",
        "fcmpeq",
    }

    # Every control transfer has one delay slot.  An annulled branch skips
    # its slot when it is not taken (always, for `ba,a`), so stepping one
    # of these may also run the instruction after it; that is preferable to
    # stopping between a branch and its slot, which loses the branch.
    delay_slot_mnemonics = _with_annul(_BRANCHES) | {
        "call",
        "jmp",
        "jmpl",
        "ret",
        "retl",
        "rett",
    }

    pc_register = SPARC_PROGRAM_COUNTER_REGISTER
    sp_register = SPARC_STACK_POINTER_ALIAS

    # %g0 is hardwired to zero, %o6/%i6 are the stack and frame pointers,
    # and %o7/%i7 hold return addresses.
    general_purpose_registers = [
        r for r in SPARC_WINDOW_REGISTERS if r not in ("g0", "o6", "o7", "i6", "i7")
    ]

    registers = {
        **{r: RegisterDef(name=r, size=4) for r in SPARC_WINDOW_REGISTERS},
        **{
            alias: RegisterAliasDef(name=alias, parent=parent, size=4, offset=0)
            for alias, parent in SPARC_REGISTER_ALIASES.items()
        },
        SPARC_PROGRAM_COUNTER_REGISTER: RegisterDef(
            name=SPARC_PROGRAM_COUNTER_REGISTER, size=4
        ),
        SPARC_NEXT_PROGRAM_COUNTER_REGISTER: RegisterDef(
            name=SPARC_NEXT_PROGRAM_COUNTER_REGISTER, size=4
        ),
        SPARC_MULTIPLY_STEP_REGISTER: RegisterDef(
            name=SPARC_MULTIPLY_STEP_REGISTER, size=4
        ),
    }
