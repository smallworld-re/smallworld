import inspect 
import capstone
import unicorn

from .machdef import UnicornMachineDef,populate_registers
from ....platforms import Byteorder
from ....arch import amd64_arch

class AMD64MachineDef(UnicornMachineDef):
    """Unicorn machine definition for amd64"""

    arch = "x86"
    mode = "64"
    byteorder = Byteorder.LITTLE

    uc_arch = unicorn.UC_ARCH_X86
    uc_mode = unicorn.UC_MODE_64

    cs_arch = capstone.CS_ARCH_X86
    cs_mode = capstone.CS_MODE_64

    pc_reg = "rip"

    arch_info = amd64_arch.info
    unicorn_consts = unicorn.x86_const

    _registers = populate_registers(arch_info, unicorn_consts)
    
