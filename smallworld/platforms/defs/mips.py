import typing

import capstone

from ..platforms import Architecture, Byteorder
from .platformdef import PlatformDef, RegisterAliasDef, RegisterDef

# NOTE: mips32 has two major ISA variants.
#
# The Debian standard is built around mips32r2.
#
# There's a newer specification mips32r6 that adds and deprecates
# a number of instructions, amongst other changes.
#
# There are older ISA variants that are still in use
# because no one updates their hardware.
#
# This definition will focus on mips32r2
# If you need support for r6, please submit a ticket.

# NOTE: MIPS registers don't really have canonical uses, or canonical names.
# Their names are assigned based on the purpose they serve
# in a specific ABI.
#
# Thus far, I've found two mips32 ABIs:
#
# o32 is the original ABI.  It assigns four argument registers.
#
# n32 is a back-port of the n64 ABI, which assigns eight argument registers.
# This one's not super-popular.


class MIPSO32PlatformDef(PlatformDef):
    # Abstract MIPS platform definition based on the o32 ABI.
    architecture = Architecture.MIPS32

    address_size = 4

    capstone_arch = capstone.CS_ARCH_MIPS
    capstone_mode = capstone.CS_MODE_MIPS32

    conditional_branch_mnemonics = {
        # Conditional branch
        "beq",
        "beqz",
        "bne",
        "bgez",
        "bgtz",
        "blez",
        "bltz",
        # Conditional branch-and-link
        "bgezal",
        "bltzal"
        # Likely conditional branch
        # Skip the delay slot if they are not taken.
        "beql",
        "bnel",
        "bgezl",
        "bgtzl",
        "blezl",
        "bltzl",
        # Likely conditional branch-and-link
        # Skip the delay slot if they are not taken
        "bgezall",
        "bltzall",
    }

    compare_mnemonics = {
        # MIPS doesn't really have integer comparison instructions
        # All of the conditional branches include a comparsion
        # relative to zero; the compiler needs to reduce
        # all conditional tests to comparisons against zero.
        # Floating-point comparison
        # Save to FCC
        # NOTE: Unlike branches, compares only support eq, lt, and le
        "c.eq.s",
        "c.eq.d",
        "c.eq.ps",
        "c.lt.s",
        "c.lt.d",
        "c.lt.ps",
        "c.le.s",
        "c.le.d",
        "c.le.ps",
        # Floating-point comparison
        # Save to FPR
        "cmp.eq.s",
        "cmp.eq.d",
        "cmp.eq.ps",
        "cmp.lt.s",
        "cmp.lt.d",
        "cmp.lt.ps",
        "cmp.le.s",
        "cmp.le.d",
        "cmp.le.ps",
    }

    delay_slot_mnemonics = {
        "b",
        "bal",
        "j",
        "jr",
        "jal",
        "jalr",
    } | conditional_branch_mnemonics

    pc_register = "pc"
    sp_register = "sp"

    # Special registers
    # zero: Hard-wired to zero
    # at: Reserved for assembler
    # sp: Stack pointer
    # gp: Global pointer
    # kX: Reserved for kernel on most platforms
    # fX: Floating-point registers
    # aX: Accumulator registers used in multiplication
    general_purpose_registers = [
        "v0",
        "v1",
        "a0",
        "a1",
        "a2",
        "a3",
        "t0",
        "t1",
        "t2",
        "t3",
        "t4",
        "t5",
        "t6",
        "t7",
        "t8",
        "t9",
        "s0",
        "s1",
        "s2",
        "s3",
        "s4",
        "s5",
        "s6",
        "s7",
        "s8",
    ]

    @property
    def registers(self) -> typing.Dict[str, RegisterDef]:
        return self._registers

    def __init__(self):
        # For analysis purposes, the
        self._registers = {
            # *** General-Purpose Registers ***
            # Assembler-Temporary Register
            "at": RegisterDef(name="at", size=4),
            "1": RegisterAliasDef(name="1", parent="at", size=4, offset=0),
            # Return Value Registers
            "v0": RegisterDef(name="v0", size=4),
            "2": RegisterAliasDef(name="2", parent="v0", size=4, offset=0),
            "v1": RegisterDef(name="v1", size=4),
            "3": RegisterAliasDef(name="3", parent="v1", size=4, offset=0),
            # Argument Registers
            "a0": RegisterDef(name="a0", size=4),
            "4": RegisterAliasDef(name="4", parent="a0", size=4, offset=0),
            "a1": RegisterDef(name="a1", size=4),
            "5": RegisterAliasDef(name="5", parent="a1", size=4, offset=0),
            "a2": RegisterDef(name="a2", size=4),
            "6": RegisterAliasDef(name="6", parent="a2", size=4, offset=0),
            "a3": RegisterDef(name="a3", size=4),
            "7": RegisterAliasDef(name="7", parent="a3", size=4, offset=0),
            # Temporary Registers
            "t0": RegisterDef(name="t0", size=4),
            "8": RegisterAliasDef(name="8", parent="t0", size=4, offset=0),
            "t1": RegisterDef(name="t1", size=4),
            "9": RegisterAliasDef(name="9", parent="t1", size=4, offset=0),
            "t2": RegisterDef(name="t2", size=4),
            "10": RegisterAliasDef(name="10", parent="t2", size=4, offset=0),
            "t3": RegisterDef(name="t3", size=4),
            "11": RegisterAliasDef(name="11", parent="t3", size=4, offset=0),
            "t4": RegisterDef(name="t4", size=4),
            "12": RegisterAliasDef(name="12", parent="t4", size=4, offset=0),
            "t5": RegisterDef(name="t5", size=4),
            "13": RegisterAliasDef(name="13", parent="t5", size=4, offset=0),
            "t6": RegisterDef(name="t6", size=4),
            "14": RegisterAliasDef(name="14", parent="t6", size=4, offset=0),
            "t7": RegisterDef(name="t7", size=4),
            "15": RegisterAliasDef(name="15", parent="t7", size=4, offset=0),
            # NOTE: These numbers aren't out of order.
            # t8 and t9 are later in the register file than t0 - t7.
            "t8": RegisterDef(name="t8", size=4),
            "24": RegisterAliasDef(name="24", parent="t8", size=4, offset=0),
            "t9": RegisterDef(name="t9", size=4),
            "25": RegisterAliasDef(name="25", parent="t9", size=4, offset=0),
            # Saved Registers
            "s0": RegisterDef(name="s0", size=4),
            "16": RegisterAliasDef(name="16", parent="s0", size=4, offset=0),
            "s1": RegisterDef(name="s1", size=4),
            "17": RegisterAliasDef(name="17", parent="s1", size=4, offset=0),
            "s2": RegisterDef(name="s2", size=4),
            "18": RegisterAliasDef(name="18", parent="s2", size=4, offset=0),
            "s3": RegisterDef(name="s3", size=4),
            "19": RegisterAliasDef(name="19", parent="s3", size=4, offset=0),
            "s4": RegisterDef(name="s4", size=4),
            "20": RegisterAliasDef(name="20", parent="s4", size=4, offset=0),
            "s5": RegisterDef(name="s5", size=4),
            "21": RegisterAliasDef(name="21", parent="s5", size=4, offset=0),
            "s6": RegisterDef(name="s6", size=4),
            "22": RegisterAliasDef(name="22", parent="s6", size=4, offset=0),
            "s7": RegisterDef(name="s7", size=4),
            "23": RegisterAliasDef(name="23", parent="s7", size=4, offset=0),
            # NOTE: Register #30 was originally the Frame Pointer.
            # It's been re-aliased as s8, since many ABIs don't use the frame pointer.
            # Unicorn and Sleigh prefer to use the alias s8,
            # so it should be the base register.
            "s8": RegisterDef(name="s8", size=4),
            "fp": RegisterAliasDef(name="fp", parent="s8", size=4, offset=0),
            "30": RegisterAliasDef(name="30", parent="s8", size=4, offset=0),
            # Kernel-reserved Registers
            "k0": RegisterDef(name="k0", size=4),
            "26": RegisterAliasDef(name="26", parent="k0", size=4, offset=0),
            "k1": RegisterDef(name="k1", size=4),
            "27": RegisterAliasDef(name="27", parent="k1", size=4, offset=0),
            # *** Pointer Registers ***
            # Zero register
            "zero": RegisterDef(name="zero", size=4),
            "0": RegisterAliasDef(name="0", parent="zero", size=4, offset=0),
            # Global Offset Pointer
            "gp": RegisterDef(name="gp", size=4),
            "28": RegisterAliasDef(name="28", parent="gp", size=4, offset=0),
            # Stack Pointer
            "sp": RegisterDef(name="sp", size=4),
            "29": RegisterAliasDef(name="29", parent="sp", size=4, offset=0),
            # Return Address
            "ra": RegisterDef(name="ra", size=4),
            "31": RegisterAliasDef(name="31", parent="ra", size=4, offset=0),
            # Program Counter
            "pc": RegisterDef(name="pc", size=4),
            # NOTE: MIPS has no ALU flags or status register
            # It doesn't have a non-privileged status register,
            # and the conditional tests write the result to a general register.
            # *** Floating Point Registers ***
            "f0": RegisterDef(name="f0", size=8),
            "f1": RegisterDef(name="f1", size=8),
            "f2": RegisterDef(name="f2", size=8),
            "f3": RegisterDef(name="f3", size=8),
            "f4": RegisterDef(name="f4", size=8),
            "f5": RegisterDef(name="f5", size=8),
            "f6": RegisterDef(name="f6", size=8),
            "f7": RegisterDef(name="f7", size=8),
            "f8": RegisterDef(name="f8", size=8),
            "f9": RegisterDef(name="f9", size=8),
            "f10": RegisterDef(name="f10", size=8),
            "f11": RegisterDef(name="f11", size=8),
            "f12": RegisterDef(name="f12", size=8),
            "f13": RegisterDef(name="f13", size=8),
            "f14": RegisterDef(name="f14", size=8),
            "f15": RegisterDef(name="f15", size=8),
            "f16": RegisterDef(name="f16", size=8),
            "f17": RegisterDef(name="f17", size=8),
            "f18": RegisterDef(name="f18", size=8),
            "f19": RegisterDef(name="f19", size=8),
            "f20": RegisterDef(name="f20", size=8),
            "f21": RegisterDef(name="f21", size=8),
            "f22": RegisterDef(name="f22", size=8),
            "f23": RegisterDef(name="f23", size=8),
            "f24": RegisterDef(name="f24", size=8),
            "f25": RegisterDef(name="f25", size=8),
            "f26": RegisterDef(name="f26", size=8),
            "f27": RegisterDef(name="f27", size=8),
            "f28": RegisterDef(name="f28", size=8),
            "f29": RegisterDef(name="f29", size=8),
            "f30": RegisterDef(name="f30", size=8),
            "f31": RegisterDef(name="f31", size=8),
            # *** Floating Point Control Registers ***
            "fir": RegisterDef(name="fir", size=4),
            "fcsr": RegisterDef(name="fcsr", size=4),
            "fexr": RegisterDef(name="fexr", size=4),
            "fenr": RegisterDef(name="fenr", size=4),
            "fccr": RegisterDef(name="fccr", size=4),
            # TODO: MIPS has a boatload of extensions with their own registers.
        }


class MIPS32EL(MIPSO32PlatformDef):
    byteorder = Byteorder.LITTLE

    def __init__(self):
        super().__init__()
        self._registers |= {
            # *** Accumulator Registers ***
            # MIPS uses these to implement 64-bit results
            # from 32-bit multiplication, amongst others.
            "ac0": RegisterDef(name="ac0", size=8),
            "lo0": RegisterAliasDef(name="lo0", parent="ac0", size=4, offset=0),
            "hi0": RegisterAliasDef(name="hi0", parent="ac0", size=4, offset=4),
            "ac1": RegisterDef(name="ac1", size=8),
            "lo1": RegisterAliasDef(name="lo1", parent="ac1", size=4, offset=0),
            "hi1": RegisterAliasDef(name="hi1", parent="ac1", size=4, offset=4),
            "ac2": RegisterDef(name="ac2", size=8),
            "lo2": RegisterAliasDef(name="lo2", parent="ac2", size=4, offset=0),
            "hi2": RegisterAliasDef(name="hi2", parent="ac2", size=4, offset=4),
            "ac3": RegisterDef(name="ac3", size=8),
            "lo3": RegisterAliasDef(name="lo3", parent="ac3", size=4, offset=0),
            "hi3": RegisterAliasDef(name="hi3", parent="ac3", size=4, offset=4),
        }


class MIPS32BE(MIPSO32PlatformDef):
    byteorder = Byteorder.BIG

    capstone_mode = capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN

    def __init__(self):
        super().__init__()
        self._registers |= {
            # *** Accumulator Registers ***
            # MIPS uses these to implement 64-bit results
            # from 32-bit multiplication, amongst others.
            "ac0": RegisterDef(name="ac0", size=8),
            "hi0": RegisterAliasDef(name="hi0", parent="ac0", size=4, offset=0),
            "lo0": RegisterAliasDef(name="lo0", parent="ac0", size=4, offset=4),
            "ac1": RegisterDef(name="ac1", size=8),
            "hi1": RegisterAliasDef(name="hi1", parent="ac1", size=4, offset=0),
            "lo1": RegisterAliasDef(name="lo1", parent="ac1", size=4, offset=4),
            "ac2": RegisterDef(name="ac2", size=8),
            "hi2": RegisterAliasDef(name="hi2", parent="ac2", size=4, offset=0),
            "lo2": RegisterAliasDef(name="lo2", parent="ac2", size=4, offset=4),
            "ac3": RegisterDef(name="ac3", size=8),
            "hi3": RegisterAliasDef(name="hi3", parent="ac3", size=4, offset=0),
            "lo3": RegisterAliasDef(name="lo3", parent="ac3", size=4, offset=4),
        }
