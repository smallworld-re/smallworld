import typing

import capstone

from ..platforms import Architecture, Byteorder
from .platformdef import PlatformDef, RegisterAliasDef, RegisterDef

# NOTE: RiscV is designed to be an extensible language.
# The core ISA is incredibly simple,
# with a large number of optional extensions available
# to chip manufacturers
#
# Support for any specific extension depends on the emulator.

# ABI names for the integer registers, indexed by register number.
#
# Special registers:
# - x0 is wired to zero
# - x1 is the link register
#   NOTE: ra is the official name; lr might be an angr invention.
# - x2 is the stack pointer
# - x3 is the global pointer
# - x4 is the thread pointer
# - x5-x7 and x28-x31 are temporary registers
# - x8, x9 and x18-x27 are callee-saved registers
# - x10-x17 are arguments 0-7
RISCV_GPR_ABI_NAMES = (
    ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1"]
    + [f"a{i}" for i in range(0, 8)]
    + [f"s{i}" for i in range(2, 12)]
    + [f"t{i}" for i in range(3, 7)]
)

# ABI names for the floating-point registers, indexed by register number.
#
# - f0-f7 and f28-f31 are temporary registers
# - f8, f9 and f18-f27 are callee-saved registers
# - f10-f17 are arguments 0-7
RISCV_FPR_ABI_NAMES = (
    [f"ft{i}" for i in range(0, 8)]
    + ["fs0", "fs1"]
    + [f"fa{i}" for i in range(0, 8)]
    + [f"fs{i}" for i in range(2, 12)]
    + [f"ft{i}" for i in range(8, 12)]
)


def riscv_registers(xlen: int) -> typing.Dict[str, RegisterDef]:
    """Build the register table for a RiscV CPU.

    Arguments:
        xlen: Width of the integer registers and pc in bytes

    Returns:
        The register definitions, keyed by name
    """
    registers: typing.Dict[str, RegisterDef] = {}
    # *** General-Purpose Registers ***
    for i, alias in enumerate(RISCV_GPR_ABI_NAMES):
        name = f"x{i}"
        registers[name] = RegisterDef(name=name, size=xlen)
        registers[alias] = RegisterAliasDef(
            name=alias, parent=name, size=xlen, offset=0
        )
    # *** Program Counter ***
    registers["pc"] = RegisterDef(name="pc", size=xlen)
    # *** Floating-Point Registers ***
    # NOTE: These are sized for the "D" extension (FLEN = 64)
    # regardless of XLEN, since RV32GC and RV64GC both include it.
    for i, alias in enumerate(RISCV_FPR_ABI_NAMES):
        name = f"f{i}"
        registers[name] = RegisterDef(name=name, size=8)
        registers[alias] = RegisterAliasDef(name=alias, parent=name, size=8, offset=0)
    # *** Vector Registers ***
    # NOTE: These exist, but are not supported
    # *** Control and Status Registers ***
    # NOTE: These exist, but aren't supported.
    return registers


class RiscV(PlatformDef):
    """Common definitions for all RiscV platforms."""

    byteorder = Byteorder.LITTLE

    capstone_arch = capstone.CS_ARCH_RISCV

    conditional_branch_mnemonics = {
        # Core conditional branch instructions
        "beq",
        "bne",
        "blt",
        "bltu",
        "ble",
        "bleu",
        "bgt",
        "bgtu",
        "bge",
        "bgeu",
        # The names capstone gives comparisons against zero
        "beqz",
        "bnez",
        "blez",
        "bgez",
        "bltz",
        "bgtz",
        # Compressed ("C" extension) branches
        "c.beqz",
        "c.bnez",
    }

    # RiscV core has no dedicated compare instructions
    # (they're rather smug about this fact).
    #
    # - The "Zicond" extension adds conditional move instructions.
    # - The "Zacas" extension adds compare-exchange instructions
    compare_mnemonics = set()

    pc_register = "pc"
    sp_register = "sp"

    general_purpose_registers = [f"x{i}" for i in range(0, 32)]


class RiscV32(RiscV):
    architecture = Architecture.RISCV32
    ghidra_language_id = "RISCV:LE:32:default"

    address_size = 4

    # RV32GC includes the "C" extension's compressed instructions.
    capstone_mode = capstone.CS_MODE_RISCV32 | capstone.CS_MODE_RISCVC

    registers = riscv_registers(4)


class RiscV64(RiscV):
    architecture = Architecture.RISCV64
    ghidra_language_id = "RISCV:LE:64:default"

    address_size = 8

    # Toolchains build RV64GC, with the "C" extension's compressed instructions.
    capstone_mode = capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC

    registers = riscv_registers(8)
