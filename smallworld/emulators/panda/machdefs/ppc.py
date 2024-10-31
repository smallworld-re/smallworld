import capstone

from ....platforms import Architecture, Byteorder
from .machdef import PandaMachineDef


class PowerPCMachineDef(PandaMachineDef):
    byteorder = Byteorder.BIG

    cs_arch = capstone.CS_ARCH_PPC
    cs_mode = capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN

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
    }
    _registers = {i: j for i, j in _registers_mapping.items()}
    _registers = _registers | {i: i for i in _registers_identity}


class PowerPC32MachineDef(PowerPCMachineDef):
    arch = Architecture.POWERPC32
    cs_mode = capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN
    cpu = "ppc32"


# TODO: Do we have a panda PPC 64 bit cpu?
class PowerPC64MachineDef(PowerPCMachineDef):
    arch = Architecture.POWERPC64
    cs_mode = capstone.CS_MODE_64 | capstone.CS_MODE_BIG_ENDIAN
    # cpu = "970"
