import capstone
import pandare

from ....platforms import Architecture, Byteorder
from .machdef import PandaMachineDef


class ARMMachineDef(PandaMachineDef):
    cs_arch = capstone.CS_ARCH_ARM
    cs_mode = capstone.CS_MODE_ARM

    pc_reg = "ip"

    panda_arch_str = "arm"
    # We don't need this
    panda_arch = pandare.arch.ArmArch(None)

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


class ARMMachineMixinM:
    """Mixin for ARM M-series machine models"""

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # NOTE: PSR is aliased to CPSR
                # This is an artifact of the fact that Unicorn
                # seems to emulate a mash-up of M- and A-series arm.
                "psr",
                "primask",
                "basepri",
                "faultmask",
                "control",
                "msp",
                "psp",
            }
        )


class ARMv5TMachineDef(ARMMachineDef):
    arch = Architecture.ARM_V5T
    byteorder = Byteorder.LITTLE


class ARMv7MMachineDef(ARMMachineDef):
    arch = Architecture.ARM_V7M
    byteorder = Byteorder.LITTLE
