import capstone
import unicorn

from .machdef import UnicornMachineDef


class i386MachineDef(UnicornMachineDef):
    """Unicorn machine definition for i386"""

    arch = "x86"
    mode = "32"
    byteorder = "little"

    uc_arch = unicorn.UC_ARCH_X86
    uc_mode = unicorn.UC_MODE_32

    cs_arch = capstone.CS_ARCH_X86
    cs_mode = capstone.CS_MODE_32

    pc_reg = "eip"

    _registers = {
        "eax": unicorn.x86_const.UC_X86_REG_EAX,
        "ax": unicorn.x86_const.UC_X86_REG_AX,
        "al": unicorn.x86_const.UC_X86_REG_AL,
        "ah": unicorn.x86_const.UC_X86_REG_AH,
        "ebx": unicorn.x86_const.UC_X86_REG_EBX,
        "bx": unicorn.x86_const.UC_X86_REG_BX,
        "bl": unicorn.x86_const.UC_X86_REG_BL,
        "bh": unicorn.x86_const.UC_X86_REG_BH,
        "ecx": unicorn.x86_const.UC_X86_REG_ECX,
        "cx": unicorn.x86_const.UC_X86_REG_CX,
        "cl": unicorn.x86_const.UC_X86_REG_CL,
        "ch": unicorn.x86_const.UC_X86_REG_CH,
        "edx": unicorn.x86_const.UC_X86_REG_EDX,
        "dx": unicorn.x86_const.UC_X86_REG_DX,
        "dl": unicorn.x86_const.UC_X86_REG_DL,
        "dh": unicorn.x86_const.UC_X86_REG_DH,
        "esi": unicorn.x86_const.UC_X86_REG_ESI,
        "si": unicorn.x86_const.UC_X86_REG_SI,
        "sil": unicorn.x86_const.UC_X86_REG_SIL,
        "edi": unicorn.x86_const.UC_X86_REG_EDI,
        "di": unicorn.x86_const.UC_X86_REG_DI,
        "dil": unicorn.x86_const.UC_X86_REG_DIL,
        "ebp": unicorn.x86_const.UC_X86_REG_EBP,
        "bp": unicorn.x86_const.UC_X86_REG_BP,
        "bpl": unicorn.x86_const.UC_X86_REG_BPL,
        "esp": unicorn.x86_const.UC_X86_REG_ESP,
        "sp": unicorn.x86_const.UC_X86_REG_SP,
        "spl": unicorn.x86_const.UC_X86_REG_SPL,
        "eip": unicorn.x86_const.UC_X86_REG_EIP,
        "ip": unicorn.x86_const.UC_X86_REG_IP,
        "cs": unicorn.x86_const.UC_X86_REG_CS,
        "ds": unicorn.x86_const.UC_X86_REG_DS,
        "es": unicorn.x86_const.UC_X86_REG_ES,
        "fs": unicorn.x86_const.UC_X86_REG_FS,
        "gs": unicorn.x86_const.UC_X86_REG_GS,
        "eflags": unicorn.x86_const.UC_X86_REG_EFLAGS,
        "flags": unicorn.x86_const.UC_X86_REG_FLAGS,
        "cr0": unicorn.x86_const.UC_X86_REG_CR0,
        "cr1": unicorn.x86_const.UC_X86_REG_CR1,
        "cr2": unicorn.x86_const.UC_X86_REG_CR2,
        "cr3": unicorn.x86_const.UC_X86_REG_CR3,
        "cr4": unicorn.x86_const.UC_X86_REG_CR4,
    }
