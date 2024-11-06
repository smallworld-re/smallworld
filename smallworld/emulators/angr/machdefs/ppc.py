import archinfo

from ....platforms import Architecture, Byteorder
from .machdef import AngrMachineDef


class PowerPCMachineDef(AngrMachineDef):
    byteorder = Byteorder.BIG

    pc_reg = "pc"

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
        "f0": "fpr0",
        "f1": "fpr1",
        "f2": "fpr2",
        "f3": "fpr3",
        "f4": "fpr4",
        "f5": "fpr5",
        "f6": "fpr6",
        "f7": "fpr7",
        "f8": "fpr8",
        "f9": "fpr9",
        "f10": "fpr10",
        "f11": "fpr11",
        "f12": "fpr12",
        "f13": "fpr13",
        "f14": "fpr14",
        "f15": "fpr15",
        "f16": "fpr16",
        "f17": "fpr17",
        "f18": "fpr18",
        "f19": "fpr19",
        "f20": "fpr20",
        "f21": "fpr21",
        "f22": "fpr22",
        "f23": "fpr23",
        "f24": "fpr24",
        "f25": "fpr25",
        "f26": "fpr26",
        "f27": "fpr27",
        "f28": "fpr28",
        "f29": "fpr29",
        "f30": "fpr30",
        "f31": "fpr31",
        "xer": "",
        "fpscr": "",
    }


class PowerPC32MachineDef(PowerPCMachineDef):
    arch = Architecture.POWERPC32
    angr_arch = archinfo.arch_ppc32.ArchPPC32(archinfo.Endness.BE)


class PowerPC64MachineDef(PowerPCMachineDef):
    arch = Architecture.POWERPC64
    angr_arch = archinfo.arch_ppc64.ArchPPC64(archinfo.Endness.BE)
