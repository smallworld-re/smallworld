import capstone
import unicorn

from .machdef import UnicornMachineDef
from ....platforms import Byteorder

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

    _registers = {
        "rax": (unicorn.x86_const.UC_X86_REG_RAX, "rax", 0, 8),
        "eax": (unicorn.x86_const.UC_X86_REG_EAX, "rax", 0, 4),
        "ax": (unicorn.x86_const.UC_X86_REG_AX,   "rax", 0, 2),
        "al": (unicorn.x86_const.UC_X86_REG_AL,   "rax", 0, 1),
        "ah": (unicorn.x86_const.UC_X86_REG_AH,   "rax", 1, 1),
        "rbx": (unicorn.x86_const.UC_X86_REG_RBX, "rbx", 0, 8),
        "ebx": (unicorn.x86_const.UC_X86_REG_EBX, "rbx", 0, 4),
        "bx": (unicorn.x86_const.UC_X86_REG_BX,   "rbx", 0, 2),
        "bl": (unicorn.x86_const.UC_X86_REG_BL,   "rbx", 0, 1),
        "bh": (unicorn.x86_const.UC_X86_REG_BH,   "rbx", 1, 1),
        "rcx": (unicorn.x86_const.UC_X86_REG_RCX, "rcx", 0, 8),
        "ecx": (unicorn.x86_const.UC_X86_REG_ECX, "rcx", 0, 4),
        "cx": (unicorn.x86_const.UC_X86_REG_CX,   "rcx", 0, 2),
        "cl": (unicorn.x86_const.UC_X86_REG_CL,   "rcx", 0, 1),
        "ch": (unicorn.x86_const.UC_X86_REG_CH,   "rcx", 1, 1),
        "rdx": (unicorn.x86_const.UC_X86_REG_RDX, "rdx", 0, 8),
        "edx": (unicorn.x86_const.UC_X86_REG_EDX, "rdx", 0, 4),
        "dx": (unicorn.x86_const.UC_X86_REG_DX,   "rdx", 0, 2),
        "dl": (unicorn.x86_const.UC_X86_REG_DL,   "rdx", 0, 1),
        "dh": (unicorn.x86_const.UC_X86_REG_DH,   "rdx", 1, 1),
        "r8": (unicorn.x86_const.UC_X86_REG_R8,   "r8", 0, 8),
        "r8d": (unicorn.x86_const.UC_X86_REG_R8D, "r8", 0, 4),
        "r8w": (unicorn.x86_const.UC_X86_REG_R8W, "r8", 0, 2),
        "r8b": (unicorn.x86_const.UC_X86_REG_R8B, "r8", 0, 1),
        "r9": (unicorn.x86_const.UC_X86_REG_R9,   "r9", 0, 8),
        "r9d": (unicorn.x86_const.UC_X86_REG_R9D, "r9", 0, 4),
        "r9w": (unicorn.x86_const.UC_X86_REG_R9W, "r9", 0, 2),
        "r9b": (unicorn.x86_const.UC_X86_REG_R9B, "r9", 0, 1),
        "r10": (unicorn.x86_const.UC_X86_REG_R10, "r10", 0, 8),
        "r10d": (unicorn.x86_const.UC_X86_REG_R10D, "r10", 0, 4),
        "r10w": (unicorn.x86_const.UC_X86_REG_R10W, "r10",0, 2),
        "r10b": (unicorn.x86_const.UC_X86_REG_R10B, "r10",0, 1),
        "r11": (unicorn.x86_const.UC_X86_REG_R11,   "r11",0, 8),
        "r11d": (unicorn.x86_const.UC_X86_REG_R11D, "r11",0, 4),
        "r11w": (unicorn.x86_const.UC_X86_REG_R11W, "r11",0, 2),
        "r11b": (unicorn.x86_const.UC_X86_REG_R11B, "r11",0, 1),
        "r12": (unicorn.x86_const.UC_X86_REG_R12,   "r12",0, 8),
        "r12d": (unicorn.x86_const.UC_X86_REG_R12D, "r12",0, 4),
        "r12w": (unicorn.x86_const.UC_X86_REG_R12W, "r12",0, 2),
        "r12b": (unicorn.x86_const.UC_X86_REG_R12B, "r12",0, 1),
        "r13": (unicorn.x86_const.UC_X86_REG_R13,   "r13",0, 8),
        "r13d": (unicorn.x86_const.UC_X86_REG_R13D, "r13",0, 4),
        "r13w": (unicorn.x86_const.UC_X86_REG_R13W, "r13",0, 2),
        "r13b": (unicorn.x86_const.UC_X86_REG_R13B, "r13",0, 1),
        "r14": (unicorn.x86_const.UC_X86_REG_R14,   "r14",0, 8),
        "r14d": (unicorn.x86_const.UC_X86_REG_R14D, "r14", 0, 4),
        "r14w": (unicorn.x86_const.UC_X86_REG_R14W, "r14", 0, 2),
        "r14b": (unicorn.x86_const.UC_X86_REG_R14B, "r14", 0, 1),
        "r15": (unicorn.x86_const.UC_X86_REG_R15,   "r15", 0, 8),
        "r15d": (unicorn.x86_const.UC_X86_REG_R15D, "r15", 0, 4),
        "r15w": (unicorn.x86_const.UC_X86_REG_R15W, "r15", 0, 2),
        "r15b": (unicorn.x86_const.UC_X86_REG_R15B, "r15", 0, 1),
        "rsi": (unicorn.x86_const.UC_X86_REG_RSI,   "rsi", 0, 8),
        "esi": (unicorn.x86_const.UC_X86_REG_ESI,   "rsi", 0, 4),
        "si": (unicorn.x86_const.UC_X86_REG_SI,     "rsi", 0, 2),
        "sil": (unicorn.x86_const.UC_X86_REG_SIL,   "rdi", 0, 1),
        "rdi": (unicorn.x86_const.UC_X86_REG_RDI,   "rdi", 0, 8),
        "edi": (unicorn.x86_const.UC_X86_REG_EDI,   "rdi", 0, 4),
        "di": (unicorn.x86_const.UC_X86_REG_DI,     "rdi", 0, 2),
        "dil": (unicorn.x86_const.UC_X86_REG_DIL,   "rdi", 0, 1),
        "rbp": (unicorn.x86_const.UC_X86_REG_RBP,  "rbp", 0, 8),
        "ebp": (unicorn.x86_const.UC_X86_REG_EBP,  "rbp", 0, 4),
        "bp": (unicorn.x86_const.UC_X86_REG_BP,    "rbp", 0, 2),
        "bpl": (unicorn.x86_const.UC_X86_REG_BPL,  "rbp", 0, 1),
        "rsp": (unicorn.x86_const.UC_X86_REG_RSP,  "rsp", 0, 8),
        "esp": (unicorn.x86_const.UC_X86_REG_ESP,  "rsp", 0, 4),
        "sp": (unicorn.x86_const.UC_X86_REG_SP,    "rsp", 0, 2),
        "spl": (unicorn.x86_const.UC_X86_REG_SPL,  "rsp", 0, 1),
        "rip": (unicorn.x86_const.UC_X86_REG_RIP,  "rip", 0, 8),
        "eip": (unicorn.x86_const.UC_X86_REG_EIP,  "rip", 0, 4),
        "ip": (unicorn.x86_const.UC_X86_REG_IP,    "rip", 0, 2),
        "cs": (unicorn.x86_const.UC_X86_REG_CS,    "cs", 0, 2),
        "ds": (unicorn.x86_const.UC_X86_REG_DS,    "ds", 0, 2),
        "es": (unicorn.x86_const.UC_X86_REG_ES,    "es", 0, 2),
        "fs": (unicorn.x86_const.UC_X86_REG_FS,    "fs", 0, 2),
        "gs": (unicorn.x86_const.UC_X86_REG_GS,    "fs", 0, 2),
        "rflags": (unicorn.x86_const.UC_X86_REG_RFLAGS, "rflags", 0, 8),
        "eflags": (unicorn.x86_const.UC_X86_REG_EFLAGS, "rflags", 0, 4),
        "flags": (unicorn.x86_const.UC_X86_REG_FLAGS, "rflags", 0, 2),
        "cr0": (unicorn.x86_const.UC_X86_REG_CR0, "cr0", 0, 8),
        "cr1": (unicorn.x86_const.UC_X86_REG_CR1, "cr1", 0, 8),
        "cr2": (unicorn.x86_const.UC_X86_REG_CR2, "cr2", 0, 8),
        "cr3": (unicorn.x86_const.UC_X86_REG_CR3, "cr3", 0, 8),
        "cr4": (unicorn.x86_const.UC_X86_REG_CR4, "cr4", 0, 8)
    }
