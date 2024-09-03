import capstone
import unicorn

from .machdef import UnicornMachineDef


class AMD64MachineDef(UnicornMachineDef):
    """Unicorn machine definition for amd64"""

    arch = "x86"
    mode = "64"
    byteorder = "little"

    uc_arch = unicorn.UC_ARCH_X86
    uc_mode = unicorn.UC_MODE_64

    cs_arch = capstone.CS_ARCH_X86
    cs_mode = capstone.CS_MODE_64

    pc_reg = "rip"

    _registers = {
        "rax": (unicorn.x86_const.UC_X86_REG_RAX, 0, 8)
        "eax": (unicorn.x86_const.UC_X86_REG_EAX, 0, 4)
        "ax": (unicorn.x86_const.UC_X86_REG_AX,   0, 2)
        "al": (unicorn.x86_const.UC_X86_REG_AL,   0, 1)
        "ah": (unicorn.x86_const.UC_X86_REG_AH,   1, 1)
        "rbx": (unicorn.x86_const.UC_X86_REG_RBX, 0, 8)
        "ebx": (unicorn.x86_const.UC_X86_REG_EBX, 0, 4)
        "bx": (unicorn.x86_const.UC_X86_REG_BX,   0, 2)
        "bl": (unicorn.x86_const.UC_X86_REG_BL,   0, 1)
        "bh": (unicorn.x86_const.UC_X86_REG_BH,   1, 1)
        "rcx": (unicorn.x86_const.UC_X86_REG_RCX, 0, 8)
        "ecx": (unicorn.x86_const.UC_X86_REG_ECX, 0, 4)
        "cx": (unicorn.x86_const.UC_X86_REG_CX,   0, 2)
        "cl": (unicorn.x86_const.UC_X86_REG_CL,   0, 1)
        "ch": (unicorn.x86_const.UC_X86_REG_CH,   1, 1)
        "rdx": (unicorn.x86_const.UC_X86_REG_RDX, 0, 8)
        "edx": (unicorn.x86_const.UC_X86_REG_EDX, 0, 4)
        "dx": (unicorn.x86_const.UC_X86_REG_DX,   0, 2)
        "dl": (unicorn.x86_const.UC_X86_REG_DL,   0, 1)
        "dh": (unicorn.x86_const.UC_X86_REG_DH,   1, 1)
        "r8": (unicorn.x86_const.UC_X86_REG_R8,   0, 8)
        "r8d": (unicorn.x86_const.UC_X86_REG_R8D, 0, 4)
        "r8w": (unicorn.x86_const.UC_X86_REG_R8W, 0, 2)
        "r8b": (unicorn.x86_const.UC_X86_REG_R8B, 0, 1)
        "r9": (unicorn.x86_const.UC_X86_REG_R9,   0, 8)
        "r9d": (unicorn.x86_const.UC_X86_REG_R9D, 0, 4)
        "r9w": (unicorn.x86_const.UC_X86_REG_R9W, 0, 2)
        "r9b": (unicorn.x86_const.UC_X86_REG_R9B, 0, 1)
        "r10": (unicorn.x86_const.UC_X86_REG_R10,   0, 8)
        "r10d": (unicorn.x86_const.UC_X86_REG_R10D, 0, 4)
        "r10w": (unicorn.x86_const.UC_X86_REG_R10W, 0, 2)
        "r10b": (unicorn.x86_const.UC_X86_REG_R10B, 0, 1)
        "r11": (unicorn.x86_const.UC_X86_REG_R11,   0, 8)
        "r11d": (unicorn.x86_const.UC_X86_REG_R11D, 0, 4)
        "r11w": (unicorn.x86_const.UC_X86_REG_R11W, 0, 2)
        "r11b": (unicorn.x86_const.UC_X86_REG_R11B, 0, 1)
        "r12": (unicorn.x86_const.UC_X86_REG_R12,   0, 8)
        "r12d": (unicorn.x86_const.UC_X86_REG_R12D, 0, 4)
        "r12w": (unicorn.x86_const.UC_X86_REG_R12W, 0, 2)
        "r12b": (unicorn.x86_const.UC_X86_REG_R12B, 0, 1)
        "r13": (unicorn.x86_const.UC_X86_REG_R13,   0, 8)
        "r13d": (unicorn.x86_const.UC_X86_REG_R13D, 0, 4)
        "r13w": (unicorn.x86_const.UC_X86_REG_R13W, 0, 2)
        "r13b": (unicorn.x86_const.UC_X86_REG_R13B, 0, 1)
        "r14": (unicorn.x86_const.UC_X86_REG_R14,   0, 8)
        "r14d": (unicorn.x86_const.UC_X86_REG_R14D, 0, 4)
        "r14w": (unicorn.x86_const.UC_X86_REG_R14W, 0, 2)
        "r14b": (unicorn.x86_const.UC_X86_REG_R14B, 0, 1)
        "r15": (unicorn.x86_const.UC_X86_REG_R15,   0, 8)
        "r15d": (unicorn.x86_const.UC_X86_REG_R15D, 0, 4)
        "r15w": (unicorn.x86_const.UC_X86_REG_R15W, 0, 2)
        "r15b": (unicorn.x86_const.UC_X86_REG_R15B, 0, 1)
        "rsi": (unicorn.x86_const.UC_X86_REG_RSI,   0, 8)
        "esi": (unicorn.x86_const.UC_X86_REG_ESI,   0, 4)
        "si": (unicorn.x86_const.UC_X86_REG_SI,     0, 2)
        "sil": (unicorn.x86_const.UC_X86_REG_SIL,   0, 1)
        "rdi": (unicorn.x86_const.UC_X86_REG_RDI,   0, 8)
        "edi": (unicorn.x86_const.UC_X86_REG_EDI,   0, 4)
        "di": (unicorn.x86_const.UC_X86_REG_DI,     0, 2)
        "dil": (unicorn.x86_const.UC_X86_REG_DIL,   0, 1)
        "rbp": (unicorn.x86_const.UC_X86_REG_RBP,  0, 8)
        "ebp": (unicorn.x86_const.UC_X86_REG_EBP,  0, 4)
        "bp": (unicorn.x86_const.UC_X86_REG_BP,    0, 2)
        "bpl": (unicorn.x86_const.UC_X86_REG_BPL,  0, 1)
        "rsp": (unicorn.x86_const.UC_X86_REG_RSP,  0, 8)
        "esp": (unicorn.x86_const.UC_X86_REG_ESP,  0, 4)
        "sp": (unicorn.x86_const.UC_X86_REG_SP,    0, 2)
        "spl": (unicorn.x86_const.UC_X86_REG_SPL,  0, 1)
        "rip": (unicorn.x86_const.UC_X86_REG_RIP,  0, 8)
        "eip": (unicorn.x86_const.UC_X86_REG_EIP,  0, 4)
        "ip": (unicorn.x86_const.UC_X86_REG_IP,    0, 2)
        "cs": (unicorn.x86_const.UC_X86_REG_CS,    0, 2)
        "ds": (unicorn.x86_const.UC_X86_REG_DS,    0, 2)
        "es": (unicorn.x86_const.UC_X86_REG_ES,    0, 2)
        "fs": (unicorn.x86_const.UC_X86_REG_FS,    0, 2)
        "gs": (unicorn.x86_const.UC_X86_REG_GS,    0, 2)
        "rflags": (unicorn.x86_const.UC_X86_REG_RFLAGS, 0, 8)
        "eflags": (unicorn.x86_const.UC_X86_REG_EFLAGS, 0, 4)
        "flags": (unicorn.x86_const.UC_X86_REG_FLAGS, 0, 2)
        "cr0": (unicorn.x86_const.UC_X86_REG_CR0, 0, 8)
        "cr1": (unicorn.x86_const.UC_X86_REG_CR1, 0, 8)
        "cr2": (unicorn.x86_const.UC_X86_REG_CR2, 0, 8)
        "cr3": (unicorn.x86_const.UC_X86_REG_CR3, 0, 8)
        "cr4": (unicorn.x86_const.UC_X86_REG_CR4, 0, 8)
    }
