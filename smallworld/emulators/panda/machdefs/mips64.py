import capstone

from ....platforms import Architecture, Byteorder
from .machdef import PandaMachineDef


class MIPS64MachineDef(PandaMachineDef):
    arch = Architecture.MIPS64
    cs_arch = capstone.CS_ARCH_MIPS

    # We don't need this

    # I'm going to define all the ones we are making possible as of now
    # I need to submit a PR to change to X86 32 bit and to includ eflags
    def __init__(self):
        self._registers = {
            "at": "at",
            "1": "at",
            "v0": "v0",
            "2": "v0",
            "v1": "v1",
            "3": "v1",
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
            "t0": "t0",
            "12": "t0",
            "t1": "t1",
            "13": "t1",
            "t2": "t2",
            "14": "t2",
            "t3": "t3",
            "15": "t3",
            "t8": "t8",
            "24": "t8",
            "t9": "t9",
            "25": "t9",
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
            "s8": "s8",
            "fp": "s8",
            "30": "s8",
            "k0": "k0",
            "26": "k0",
            "k1": "k1",
            "27": "k1",
            "zero": "zero",
            "0": "zero",
            "gp": "gp",
            "28": "gp",
            "sp": "sp",
            "29": "sp",
            "ra": "ra",
            "31": "ra",
            "pc": "pc",
        }


class MIPS64BEMachineDef(MIPS64MachineDef):
    byteorder = Byteorder.BIG
    panda_arch = "mips64"
    machine = "malta"
    cpu = "MIPS64R2-generic"
    cs_mode = capstone.CS_MODE_MIPS64 | capstone.CS_MODE_BIG_ENDIAN


class MIPS64ELMachineDef(MIPS64MachineDef):
    byteorder = Byteorder.LITTLE
    panda_arch = "mips64el"
    machine = "malta"
    cpu = "MIPS64R2-generic"
    cs_mode = capstone.CS_MODE_MIPS64 | capstone.CS_MODE_LITTLE_ENDIAN
