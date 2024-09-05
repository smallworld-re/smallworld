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
        # map from name of reg (or sub-part) to 4-tuple, (u, b, o, s)
        # u is the unicorn reg number
        # b is the name of full-width base register this is or is part of
        # o is start offset within full-width base register
        # s is size in bytes
        "eax": (unicorn.x86_const.UC_X86_REG_EAX, "eax", 0, 4)
        "ax": (unicorn.x86_const.UC_X86_REG_AX,   "eax", 0, 2)
        "al": (unicorn.x86_const.UC_X86_REG_AL,   "eax", 0, 1)
        "ah": (unicorn.x86_const.UC_X86_REG_AH,   "eax", 1, 1)
        "ebx": (unicorn.x86_const.UC_X86_REG_EBX, "ebx", 0, 4)
        "bx": (unicorn.x86_const.UC_X86_REG_BX,   "ebx", 0, 2)
        "bl": (unicorn.x86_const.UC_X86_REG_BL,   "ebx", 0, 1)
        "bh": (unicorn.x86_const.UC_X86_REG_BH,   "ebx", 1, 1)
        "ecx": (unicorn.x86_const.UC_X86_REG_ECX, "ecx", 0, 4)
        "cx": (unicorn.x86_const.UC_X86_REG_CX,   "ecx", 0, 2)
        "cl": (unicorn.x86_const.UC_X86_REG_CL,   "ecx", 0, 1)
        "ch": (unicorn.x86_const.UC_X86_REG_CH,   "ecx", 1, 1)
        "edx": (unicorn.x86_const.UC_X86_REG_EDX, "edx", 0, 4)
        "dx": (unicorn.x86_const.UC_X86_REG_DX,   "edx", 0, 2)
        "dl": (unicorn.x86_const.UC_X86_REG_DL,   "edx", 0, 1)
        "dh": (unicorn.x86_const.UC_X86_REG_DH,   "edx", 1, 1)
        "esi": (unicorn.x86_const.UC_X86_REG_ESI, "esi", 0, 4)
        "si": (unicorn.x86_const.UC_X86_REG_SI,   "esi", 0, 2)
        "sil": (unicorn.x86_const.UC_X86_REG_SIL, "esi", 0, 1)
        "edi": (unicorn.x86_const.UC_X86_REG_EDI, "edi", 0, 4)
        "di": (unicorn.x86_const.UC_X86_REG_DI,   "edi", 0, 2)
        "dil": (unicorn.x86_const.UC_X86_REG_DIL, "edi", 0, 1)
        "ebp": (unicorn.x86_const.UC_X86_REG_EBP, "ebp", 0, 4)
        "bp": (unicorn.x86_const.UC_X86_REG_BP,   "ebp", 0, 2)
        "bpl": (unicorn.x86_const.UC_X86_REG_BPL, "ebp", 0, 1)
        "esp": (unicorn.x86_const.UC_X86_REG_ESP, "esp", 0, 4)
        "sp": (unicorn.x86_const.UC_X86_REG_SP,   "esp", 0, 2)
        "spl": (unicorn.x86_const.UC_X86_REG_SPL, "esp", 0, 1)
        "eip": (unicorn.x86_const.UC_X86_REG_EIP, "eip", 0, 4)
        "ip": (unicorn.x86_const.UC_X86_REG_IP,   "eip", 0, 2)
        "cs": (unicorn.x86_const.UC_X86_REG_CS,   "cs", 0, 2)
        "ds": (unicorn.x86_const.UC_X86_REG_DS,   "ds", 0, 2)
        "es": (unicorn.x86_const.UC_X86_REG_ES,   "es", 0, 2)
        "fs": (unicorn.x86_const.UC_X86_REG_FS,   "fs", 0, 2)
        "gs": (unicorn.x86_const.UC_X86_REG_GS,   "gs", 0, 2)
        "eflags": (unicorn.x86_const.UC_X86_REG_EFLAGS, "eflags", 0, 4)
        "flags": (unicorn.x86_const.UC_X86_REG_FLAGS,   "eflags", 0, 2)
        "cr0": (unicorn.x86_const.UC_X86_REG_CR0, "cr0", 0, 4)
        "cr1": (unicorn.x86_const.UC_X86_REG_CR1, "cr1", 0, 4)
        "cr2": (unicorn.x86_const.UC_X86_REG_CR2, "cr2", 0, 4)
        "cr3": (unicorn.x86_const.UC_X86_REG_CR3, "cr3", 0, 4)
        "cr4": (unicorn.x86_const.UC_X86_REG_CR4, "cr4", 0, 4)
    }
