import capstone
import unicorn

from .machdef import UnicornMachineDef,populate_registers
from ....platforms import Byteorder
from ....arch import i386_arch

class i386MachineDef(UnicornMachineDef):
    """Unicorn machine definition for i386"""

    arch = "x86"
    mode = "32"
    byteorder = Byteorder.LITTLE

    uc_arch = unicorn.UC_ARCH_X86
    uc_mode = unicorn.UC_MODE_32

    cs_arch = capstone.CS_ARCH_X86
    cs_mode = capstone.CS_MODE_32

    pc_reg = "eip"

    arch_info = i386_arch.info
    unicorn_consts = unicorn.x86_const

    _registers = populate_registers(arch_info, unicorn_consts)

