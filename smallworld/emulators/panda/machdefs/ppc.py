from ....platforms import Architecture, Byteorder
from .machdef import PandaMachineDef


class PowerPCMachineDef(PandaMachineDef):
    byteorder = Byteorder.BIG

    panda_arch = "ppc"

    # I'm going to define all the ones we are making possible as of now
    # I need to submit a PR to change to X86 32 bit and to includ eflags
    _registers_identity = {
        "r0",
        "r2",
        "r3",
        "r4",
        "r5",
        "r6",
        "r7",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "r16",
        "r17",
        "r18",
        "r19",
        "r20",
        "r21",
        "r22",
        "r23",
        "r24",
        "r25",
        "r26",
        "r27",
        "r28",
        "r29",
        "r30",
        "r31",
        "cr0",
        "cr1",
        "cr2",
        "cr3",
        "cr4",
        "cr5",
        "cr6",
        "cr7",
        "pc",
        "sp",
        "lr",
        "ctr",
    }
    _registers_mapping = {
        "r1": "sp",
        "bp": "r31",
    }
    _registers_unsupported = {
        "f0",
        "f1",
        "f2",
        "f3",
        "f4",
        "f5",
        "f6",
        "f7",
        "f8",
        "f9",
        "f10",
        "f11",
        "f12",
        "f13",
        "f14",
        "f15",
        "f16",
        "f17",
        "f18",
        "f19",
        "f20",
        "f21",
        "f22",
        "f23",
        "f24",
        "f25",
        "f26",
        "f27",
        "f28",
        "f29",
        "f30",
        "f31",
        "xer",
        "fpscr",
    }
    _registers = {i: j for i, j in _registers_mapping.items()}
    _registers = _registers | {i: i for i in _registers_identity}
    _registers = _registers | {i: None for i in _registers_unsupported}


class PowerPC32MachineDef(PowerPCMachineDef):
    arch = Architecture.POWERPC32
    cpu = "ppc32"
