import archinfo

from ....platforms import Architecture, Byteorder
from .machdef import AngrMachineDef


class MIPS64MachineDef(AngrMachineDef):
    arch = Architecture.MIPS64

    pc_reg = "pc"

    # NOTE: MIPS registers have a name and a number
    # angr's machine state doesn't use the number,
    # so... name.
    # NOTE: angr's register names are wrong.
    # It follows Wikipedia's definition of the 64-bit ABI,
    # which has a4 - a7 and t0 - t3 overlapping.
    _registers = {
        # *** General-Purpose Registers ***
        # Assembler-Temporary Register
        "at": "at",
        "1": "at",
        # Return Value Registers
        "v0": "v0",
        "2": "v0",
        "v1": "v1",
        "3": "v1",
        # Argument Registers
        "a0": "a0",
        "4": "a0",
        "a1": "a1",
        "5": "a1",
        "a2": "a2",
        "6": "a2",
        "a3": "a3",
        "7": "a3",
        "a4": "a4",
        "8": "a4",
        "a5": "a5",
        "9": "a5",
        "a6": "a6",
        "10": "a6",
        "a7": "a7",
        "11": "a7",
        # Temporary Registers
        # NOTE: angr names registers 12 - 15 incorrectly.
        # Be very careful if accessing angr's state directly.
        "t0": "t4",
        "12": "t4",
        "t1": "t5",
        "13": "t5",
        "t2": "t6",
        "14": "t6",
        "t3": "t7",
        "15": "t7",
        # NOTE: These numbers aren't out of order.
        # t8 and t9 are later in the register file than t0 - t7.
        "t8": "t8",
        "24": "t8",
        "t9": "t9",
        "25": "t9",
        # Saved Registers
        "s0": "s0",
        "16": "s0",
        "s1": "s1",
        "17": "s1",
        "s2": "s2",
        "18": "s2",
        "s3": "s3",
        "19": "s3",
        "s4": "s4",
        "20": "s4",
        "s5": "s5",
        "21": "s5",
        "s6": "s6",
        "22": "s6",
        "s7": "s7",
        "23": "s7",
        # NOTE: Register #30 was originally the Frame Pointer.
        # It's been re-aliased as s8, since many ABIs don't use the frame pointer.
        # Unicorn and Sleigh prefer to use the alias s8,
        # so it should be the base register.
        "s8": "s8",
        "fp": "fp",
        "30": "fp",
        # Kernel-reserved Registers
        "k0": "k0",
        "26": "k0",
        "k1": "k1",
        "27": "k1",
        # *** Pointer Registers ***
        # Zero register
        "zero": "zero",
        "0": "zero",
        # Global Offset Pointer
        "gp": "gp",
        "28": "gp",
        # Stack Pointer
        "sp": "sp",
        "29": "sp",
        # Return Address
        "ra": "ra",
        "31": "ra",
        # Program Counter
        "pc": "pc",
        # Floating Point Registers
        "f0": "f0",
        "f1": "f1",
        "f2": "f2",
        "f3": "f3",
        "f4": "f4",
        "f5": "f5",
        "f6": "f6",
        "f7": "f7",
        "f8": "f8",
        "f9": "f9",
        "f10": "f10",
        "f11": "f11",
        "f12": "f12",
        "f13": "f13",
        "f14": "f14",
        "f15": "f15",
        "f16": "f16",
        "f17": "f17",
        "f18": "f18",
        "f19": "f19",
        "f20": "f20",
        "f21": "f21",
        "f22": "f22",
        "f23": "f23",
        "f24": "f24",
        "f25": "f25",
        "f26": "f26",
        "f27": "f27",
        "f28": "f28",
        "f29": "f29",
        "f30": "f30",
        "f31": "f31",
        # *** Floating Point Control Registers ***
        "fir": "fir",
        "fcsr": "fcsr",
        "fexr": "fexr",
        "fenr": "fenr",
        "fccr": "fccr",
        # *** Accumulator Registers ***
        # MIPS uses these to implement 64-bit results
        # from 32-bit multiplication, amongst others.
        "ac0": "ac0",
        "hi0": "hi0",
        "lo0": "lo0",
        "ac1": "ac1",
        "hi1": "hi1",
        "lo1": "lo1",
        "ac2": "ac2",
        "hi2": "hi2",
        "lo2": "lo2",
        "ac3": "ac3",
        "hi3": "hi3",
        "lo3": "lo3",
    }

    _delay_slot_opcodes = {
        "j",
        "jal",
        "jalx",
        "jalr",
        "jr",
        "beq",
        "beqz",
        "bne" "bnez",
        "bgez",
        "bgezal",
        "bgtz",
        "blez",
        "bltz",
        "bltzal",
    }

    supports_single_step = False


class MIPS64ELMachineDef(MIPS64MachineDef):
    byteorder = Byteorder.LITTLE
    angr_arch = archinfo.ArchMIPS64(archinfo.Endness.LE)


class MIPS64BEMachineDef(MIPS64MachineDef):
    byteorder = Byteorder.BIG
    angr_arch = archinfo.ArchMIPS64(archinfo.Endness.BE)
