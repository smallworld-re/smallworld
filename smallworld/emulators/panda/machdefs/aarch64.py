import capstone

from ....platforms import Architecture, Byteorder
from .machdef import PandaMachineDef


class AArch64MachineDef(PandaMachineDef):
    arch = Architecture.AARCH64
    byteorder = Byteorder.LITTLE

    cs_arch = capstone.CS_ARCH_ARM64
    cs_mode = capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN

    panda_arch = "aarch64"

    # I'm going to define all the ones we are making possible as of now
    # I need to submit a PR to change to X86 32 bit and to includ eflags
    def __init__(self):
        self._registers = {
            "x0": "x0",
            "w0": "x0",
            "x1": "x1",
            "w1": "x1",
            "x2": "x2",
            "w2": "x2",
            "x3": "x3",
            "w3": "x3",
            "x4": "x4",
            "w4": "x4",
            "x5": "x5",
            "w5": "x5",
            "x6": "x6",
            "w6": "x6",
            "x7": "x7",
            "w7": "x7",
            "x8": "xr",
            "w8": "xr",
            "xr": "xr",
            "x9": "x9",
            "w9": "x9",
            "x10": "x10",
            "w10": "x10",
            "x11": "x11",
            "w11": "x11",
            "x12": "x12",
            "w12": "x12",
            "x13": "x13",
            "w13": "x13",
            "x14": "x14",
            "w14": "x14",
            "x15": "x15",
            "w15": "x15",
            "x16": "ip0",
            "w16": "ip0",
            "ip0": "ip0",
            "x17": "ip1",
            "w17": "ip1",
            "ip1": "ip1",
            "x18": "pr",
            "w18": "pr",
            "pr": "pr",
            "x19": "x19",
            "w19": "x19",
            "x20": "x20",
            "w20": "x20",
            "x21": "x21",
            "w21": "x21",
            "x22": "x22",
            "w22": "x22",
            "x23": "x23",
            "w23": "x23",
            "x24": "x24",
            "w24": "x24",
            "x25": "x25",
            "w25": "x25",
            "x26": "x26",
            "w26": "x26",
            "x27": "x27",
            "w27": "x27",
            "x28": "x28",
            "w28": "x28",
            "x29": "fp",
            "w29": "fp",
            "fp": "fp",
            "x30": "lr",
            "w30": "lr",
            "lr": "lr",
            "pc": "pc",
            "sp": "sp",
            "wsp": "sp",
        }

        self._registers = {i: j for i, j in self._registers.items()}
