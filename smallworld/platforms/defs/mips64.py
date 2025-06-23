import typing

import capstone

from ..platforms import Architecture, Byteorder
from .platformdef import PlatformDef, RegisterAliasDef, RegisterDef

# MIPS registers don't really have canonical uses, or canonical names.
# Their names are assigned based on the purpose they serve
# in a specific ABI.
#
# Thus far, I've found three mips64 ABIs:
#
# n64 is the original 64-bit ABI (designed for the Nintendo 64).
# It allows for up to eight argument registers,
# at the cost of fewer temporary registers.
#
# o64 is a forward-port of the o32 ABI used by mips32.
#
# There's another GNU ABI that's similar to n64,
# but renames the remaining temporary registers differently.


class MIPSN64PlatformDef(PlatformDef):
    # Abstract MIPS64 platform definition based on the n64 ABI.
    architecture = Architecture.MIPS64

    address_size = 8

    capstone_arch = capstone.CS_ARCH_MIPS
    capstone_mode = capstone.CS_MODE_MIPS64

    pc_register = "pc"

    general_purpose_registers = [
        "v0",
        "v1",
        "a0",
        "a1",
        "a2",
        "a3",
        "a4",
        "a5",
        "a6",
        "a7",
        "t0",
        "t1",
        "t2",
        "t3",
        "t4",
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
        super().__init__()
        self._registers = {
            # *** General-Purpose Registers ***
            # Assembler-Temporary Register
            "at": RegisterDef(name="at", size=8),
            "1": RegisterAliasDef(name="1", parent="at", size=8, offset=0),
            # Return Value Registers
            "v0": RegisterDef(name="v0", size=8),
            "2": RegisterAliasDef(name="2", parent="v0", size=8, offset=0),
            "v1": RegisterDef(name="v1", size=8),
            "3": RegisterAliasDef(name="3", parent="v1", size=8, offset=0),
            # Argument Registers
            "a0": RegisterDef(name="a0", size=8),
            "4": RegisterAliasDef(name="4", parent="a0", size=8, offset=0),
            "a1": RegisterDef(name="a1", size=8),
            "5": RegisterAliasDef(name="5", parent="a1", size=8, offset=0),
            "a2": RegisterDef(name="a2", size=8),
            "6": RegisterAliasDef(name="6", parent="a2", size=8, offset=0),
            "a3": RegisterDef(name="a3", size=8),
            "7": RegisterAliasDef(name="7", parent="a3", size=8, offset=0),
            "a4": RegisterDef(name="a4", size=8),
            "8": RegisterAliasDef(name="8", parent="a4", size=8, offset=0),
            "a5": RegisterDef(name="a5", size=8),
            "9": RegisterAliasDef(name="9", parent="a5", size=8, offset=0),
            "a6": RegisterDef(name="a6", size=8),
            "10": RegisterAliasDef(name="10", parent="a6", size=8, offset=0),
            "a7": RegisterDef(name="a7", size=8),
            "11": RegisterAliasDef(name="11", parent="a7", size=8, offset=0),
            # Temporary Registers
            "t0": RegisterDef(name="t0", size=8),
            "12": RegisterAliasDef(name="12", parent="t0", size=8, offset=0),
            "t1": RegisterDef(name="t1", size=8),
            "13": RegisterAliasDef(name="13", parent="t1", size=8, offset=0),
            "t2": RegisterDef(name="t2", size=8),
            "14": RegisterAliasDef(name="14", parent="t2", size=8, offset=0),
            "t3": RegisterDef(name="t3", size=8),
            "15": RegisterAliasDef(name="15", parent="t3", size=8, offset=0),
            # NOTE: These numbers aren't out of order.
            # t8 and t9 are later in the register file than t0 - t3.
            # The gap is also intentional; t4 - t7 were sacrificed
            # to make room for a4 - a7
            "t8": RegisterDef(name="t8", size=8),
            "24": RegisterAliasDef(name="24", parent="t8", size=8, offset=0),
            "t9": RegisterDef(name="t9", size=8),
            "25": RegisterAliasDef(name="25", parent="t9", size=8, offset=0),
            # Saved Registers
            "s0": RegisterDef(name="s0", size=8),
            "16": RegisterAliasDef(name="16", parent="s0", size=8, offset=0),
            "s1": RegisterDef(name="s1", size=8),
            "17": RegisterAliasDef(name="17", parent="s1", size=8, offset=0),
            "s2": RegisterDef(name="s2", size=8),
            "18": RegisterAliasDef(name="18", parent="s2", size=8, offset=0),
            "s3": RegisterDef(name="s3", size=8),
            "19": RegisterAliasDef(name="19", parent="s3", size=8, offset=0),
            "s4": RegisterDef(name="s4", size=8),
            "20": RegisterAliasDef(name="20", parent="s4", size=8, offset=0),
            "s5": RegisterDef(name="s5", size=8),
            "21": RegisterAliasDef(name="21", parent="s5", size=8, offset=0),
            "s6": RegisterDef(name="s6", size=8),
            "22": RegisterAliasDef(name="22", parent="s6", size=8, offset=0),
            "s7": RegisterDef(name="s7", size=8),
            "23": RegisterAliasDef(name="23", parent="s7", size=8, offset=0),
            # NOTE: Register #30 was originally the Frame Pointer.
            # It's been re-aliased as s8, since many ABIs don't use the frame pointer.
            "s8": RegisterDef(name="s8", size=8),
            "fp": RegisterAliasDef(name="fp", parent="s8", size=8, offset=0),
            "30": RegisterAliasDef(name="30", parent="s8", size=8, offset=0),
            # Kernel-reserved Registers
            "k0": RegisterDef(name="k0", size=8),
            "26": RegisterAliasDef(name="26", parent="k0", size=8, offset=0),
            "k1": RegisterDef(name="k1", size=8),
            "27": RegisterAliasDef(name="27", parent="k1", size=8, offset=0),
            # *** Pointer Registers ***
            # Zero register
            "zero": RegisterDef(name="zero", size=8),
            "0": RegisterAliasDef(name="0", parent="zero", size=8, offset=0),
            # Global Offset Pointer
            "gp": RegisterDef(name="gp", size=8),
            "28": RegisterAliasDef(name="28", parent="gp", size=8, offset=0),
            # Stack Pointer
            "sp": RegisterDef(name="sp", size=8),
            "29": RegisterAliasDef(name="29", parent="sp", size=8, offset=0),
            # Return Address
            "ra": RegisterDef(name="ra", size=8),
            "31": RegisterAliasDef(name="31", parent="ra", size=8, offset=0),
            # Program Counter
            "pc": RegisterDef(name="pc", size=8),
            # *** Floating Point Registers ***
            "f1": RegisterDef(name="f1", size=8),
            "f0": RegisterDef(name="f0", size=8),
            "f3": RegisterDef(name="f3", size=8),
            "f2": RegisterDef(name="f2", size=8),
            "f5": RegisterDef(name="f5", size=8),
            "f4": RegisterDef(name="f4", size=8),
            "f7": RegisterDef(name="f7", size=8),
            "f6": RegisterDef(name="f6", size=8),
            "f9": RegisterDef(name="f9", size=8),
            "f8": RegisterDef(name="f8", size=8),
            "f11": RegisterDef(name="f11", size=8),
            "f10": RegisterDef(name="f10", size=8),
            "f13": RegisterDef(name="f13", size=8),
            "f12": RegisterDef(name="f12", size=8),
            "f15": RegisterDef(name="f15", size=8),
            "f14": RegisterDef(name="f14", size=8),
            "f17": RegisterDef(name="f17", size=8),
            "f16": RegisterDef(name="f16", size=8),
            "f19": RegisterDef(name="f19", size=8),
            "f18": RegisterDef(name="f18", size=8),
            "f21": RegisterDef(name="f21", size=8),
            "f20": RegisterDef(name="f20", size=8),
            "f23": RegisterDef(name="f23", size=8),
            "f22": RegisterDef(name="f22", size=8),
            "f25": RegisterDef(name="f25", size=8),
            "f24": RegisterDef(name="f24", size=8),
            "f27": RegisterDef(name="f27", size=8),
            "f26": RegisterDef(name="f26", size=8),
            "f29": RegisterDef(name="f29", size=8),
            "f28": RegisterDef(name="f28", size=8),
            "f31": RegisterDef(name="f31", size=8),
            "f30": RegisterDef(name="f30", size=8),
            # *** Floating Point Control Registers ***
            "fir": RegisterDef(name="fir", size=4),
            "fcsr": RegisterDef(name="fcsr", size=4),
            "fexr": RegisterDef(name="fexr", size=4),
            "fenr": RegisterDef(name="fenr", size=4),
            "fccr": RegisterDef(name="fccr", size=4),
        }


class MIPS64EL(MIPSN64PlatformDef):
    byteorder = Byteorder.LITTLE

    def __init__(self):
        super().__init__()
        self._registers |= {
            # *** Accumulator Registers ***
            # MIPS uses these to implement 128-bit results
            # from 64-bit multiplication, amongst others.
            "ac0": RegisterDef(name="ac0", size=16),
            "lo0": RegisterAliasDef(name="lo0", parent="ac0", size=8, offset=0),
            "hi0": RegisterAliasDef(name="hi0", parent="ac0", size=8, offset=8),
            "ac1": RegisterDef(name="ac1", size=16),
            "lo1": RegisterAliasDef(name="lo1", parent="ac1", size=8, offset=0),
            "hi1": RegisterAliasDef(name="hi1", parent="ac1", size=8, offset=8),
            "ac2": RegisterDef(name="ac2", size=16),
            "lo2": RegisterAliasDef(name="lo2", parent="ac2", size=8, offset=0),
            "hi2": RegisterAliasDef(name="hi2", parent="ac2", size=8, offset=8),
            "ac3": RegisterDef(name="ac3", size=16),
            "lo3": RegisterAliasDef(name="lo3", parent="ac3", size=8, offset=0),
            "hi3": RegisterAliasDef(name="hi3", parent="ac3", size=8, offset=8),
        }


class MIPS64BE(MIPSN64PlatformDef):
    byteorder = Byteorder.BIG

    capstone_mode = capstone.CS_MODE_MIPS64 | capstone.CS_MODE_BIG_ENDIAN

    def __init__(self):
        super().__init__()
        self._registers |= {
            # *** Accumulator Registers ***
            # MIPS uses these to implement 128-bit results
            # from 64-bit multiplication, amongst others.
            "ac0": RegisterDef(name="ac0", size=16),
            "hi0": RegisterAliasDef(name="hi0", parent="ac0", size=8, offset=0),
            "lo0": RegisterAliasDef(name="lo0", parent="ac0", size=8, offset=8),
            "ac1": RegisterDef(name="ac1", size=16),
            "hi1": RegisterAliasDef(name="hi1", parent="ac1", size=8, offset=0),
            "lo1": RegisterAliasDef(name="lo1", parent="ac1", size=8, offset=8),
            "ac2": RegisterDef(name="ac2", size=16),
            "hi2": RegisterAliasDef(name="hi2", parent="ac2", size=8, offset=0),
            "lo2": RegisterAliasDef(name="lo2", parent="ac2", size=8, offset=8),
            "ac3": RegisterDef(name="ac3", size=16),
            "hi3": RegisterAliasDef(name="hi3", parent="ac3", size=8, offset=0),
            "lo3": RegisterAliasDef(name="lo3", parent="ac3", size=8, offset=8),
        }
