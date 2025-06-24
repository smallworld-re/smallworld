from ....platforms import Architecture, Byteorder
from .machdef import PcodeMachineDef


class PowerPCMachineDef(PcodeMachineDef):
    byteorder = Byteorder.BIG

    _registers = {
        "r0": "r0",
        "r1": "r1",
        "sp": "sp",
        "r2": "r2",
        "r3": "r3",
        "r4": "r4",
        "r5": "r5",
        "r6": "r6",
        "r7": "r7",
        "r8": "r8",
        "r9": "r9",
        "r10": "r10",
        "r11": "r11",
        "r12": "r12",
        "r13": "r13",
        "r14": "r14",
        "r15": "r15",
        "r16": "r16",
        "r17": "r17",
        "r18": "r18",
        "r19": "r19",
        "r20": "r20",
        "r21": "r21",
        "r22": "r22",
        "r23": "r23",
        "r24": "r24",
        "r25": "r25",
        "r26": "r26",
        "r27": "r27",
        "r28": "r28",
        "r29": "r29",
        "r30": "r30",
        "r31": "r31",
        "pc": "pc",
        "lr": "lr",
        "ctr": "ctr",
        "cr0": "cr0",
        "cr1": "cr1",
        "cr2": "cr2",
        "cr3": "cr3",
        "cr4": "cr4",
        "cr5": "cr5",
        "cr6": "cr6",
        "cr7": "cr7",
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
        "xer": None,
        "fpscr": None,
    }


class PowerPC32MachineDef(PowerPCMachineDef):
    arch = Architecture.POWERPC32
    language_id = "PowerPC:BE:32:default"


class PowerPC64MachineDef(PowerPCMachineDef):
    arch = Architecture.POWERPC64
    language_id = "PowerPC:BE:64:default"
