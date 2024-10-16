import capstone
import unicorn

from ....arch import aarch64_arch
from ....platforms import Architecture, Byteorder
from .machdef import UnicornMachineDef


class AArch64MachineDef(UnicornMachineDef):
    arch = Architecture.AARCH64
    byteorder = Byteorder.LITTLE

    uc_arch = unicorn.UC_ARCH_ARM64
    uc_mode = unicorn.UC_MODE_ARM

    cs_arch = capstone.CS_ARCH_ARM64
    cs_mode = capstone.CS_MODE_ARM

    pc_reg = "pc"

    arch_info = aarch64_arch.info
    unicorn_consts = unicorn.arm64_const

