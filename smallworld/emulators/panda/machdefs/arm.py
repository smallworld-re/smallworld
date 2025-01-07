import capstone

from ....platforms import Architecture, Byteorder
from .machdef import PandaMachineDef


class ARMMachineDef(PandaMachineDef):
    cs_arch = capstone.CS_ARCH_ARM
    cs_mode = capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN

    panda_arch = "arm"

    # I'm going to define all the ones we are making possible as of now
    # I need to submit a PR to change to X86 32 bit and to includ eflags
    def __init__(self):
        self._registers = {
            "r0",
            "r1",
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
            "sp",
            "lr",
            "ip",
        }

        self._registers = {i: i for i in self._registers}
        self._registers = self._registers | {"pc": "ip"}


class ARMMachineMixinM:
    """Mixin for ARM M-series machine models"""

    def __init__(self):
        super().__init__()
        self._registers_m = {
            # NOTE: None of the expected privileged registers exist
            # "psr",
            # "primask",
            # "basepri",
            # "faultmask",
            # "control",
            # "msp",
            # "psp",
        }
        self._registers = self._registers | {i: i for i in self._registers_m}


class ARMMachineMixinA:
    """Mixin for ARM A-series machine models"""

    def __init__(self):
        super().__init__()
        # TODO: QEMU doesn't quite support what I expect.
        # I expected to see cpsr and spsr.
        # I either got the CPU model wrong, or something else is weird.
        self._registers_a = {
            "psr",
        }
        self._registers = self._registers | {i: i for i in self._registers_a}


class ARMv5TMachineDef(ARMMachineDef):
    arch = Architecture.ARM_V5T
    byteorder = Byteorder.LITTLE
    cpu = "pxa255"


# TODO: Something's very weird with Panda's Arm 7 models.
# cortex-a9 should be an A-series, but it looks more like an M-series.
# cortex-m4 looks like an M-series, but aborts; I suspect we're missing configuration.
class ARMv7AMachineDef(ARMMachineMixinA, ARMMachineDef):
    arch = Architecture.ARM_V7A
    byteorder = Byteorder.LITTLE
    cpu = "cortex-a9"


class ARMv7MMachineDef(ARMMachineMixinM, ARMMachineDef):
    arch = Architecture.ARM_V7M
    byteorder = Byteorder.LITTLE
    cpu = "cortex-m4"
