import capstone
import unicorn

from .machdef import UnicornMachineDef


class AMD64MachineDef(UnicornMachineDef):
    """Unicorn machine definition for amd64"""

    arch = "x86"
    mode = "64"
    endian = "little"

    uc_arch = unicorn.UC_ARCH_X86
    uc_mode = unicorn.UC_MODE_64

    cs_arch = capstone.CS_ARCH_X86
    cs_mode = capstone.CS_MODE_64

    pc_reg = "rip"

    _registers = {
        "rax": unicorn.x86_const.UC_X86_REG_RAX,
        "eax": unicorn.x86_const.UC_X86_REG_EAX,
        "ax": unicorn.x86_const.UC_X86_REG_AX,
        "al": unicorn.x86_const.UC_X86_REG_AL,
        "ah": unicorn.x86_const.UC_X86_REG_AH,
        "rbx": unicorn.x86_const.UC_X86_REG_RBX,
        "ebx": unicorn.x86_const.UC_X86_REG_EBX,
        "bx": unicorn.x86_const.UC_X86_REG_BX,
        "bl": unicorn.x86_const.UC_X86_REG_BL,
        "bh": unicorn.x86_const.UC_X86_REG_BH,
        "rcx": unicorn.x86_const.UC_X86_REG_RCX,
        "ecx": unicorn.x86_const.UC_X86_REG_ECX,
        "cx": unicorn.x86_const.UC_X86_REG_CX,
        "cl": unicorn.x86_const.UC_X86_REG_CL,
        "ch": unicorn.x86_const.UC_X86_REG_CH,
        "rdx": unicorn.x86_const.UC_X86_REG_RDX,
        "edx": unicorn.x86_const.UC_X86_REG_EDX,
        "dx": unicorn.x86_const.UC_X86_REG_DX,
        "dl": unicorn.x86_const.UC_X86_REG_DL,
        "dh": unicorn.x86_const.UC_X86_REG_DH,
        "r8": unicorn.x86_const.UC_X86_REG_R8,
        "r8d": unicorn.x86_const.UC_X86_REG_R8D,
        "r8w": unicorn.x86_const.UC_X86_REG_R8W,
        "r8b": unicorn.x86_const.UC_X86_REG_R8B,
        "r9": unicorn.x86_const.UC_X86_REG_R9,
        "r9d": unicorn.x86_const.UC_X86_REG_R9D,
        "r9w": unicorn.x86_const.UC_X86_REG_R9W,
        "r9b": unicorn.x86_const.UC_X86_REG_R9B,
        "r10": unicorn.x86_const.UC_X86_REG_R10,
        "r10d": unicorn.x86_const.UC_X86_REG_R10D,
        "r10w": unicorn.x86_const.UC_X86_REG_R10W,
        "r10b": unicorn.x86_const.UC_X86_REG_R10B,
        "r11": unicorn.x86_const.UC_X86_REG_R11,
        "r11d": unicorn.x86_const.UC_X86_REG_R11D,
        "r11w": unicorn.x86_const.UC_X86_REG_R11W,
        "r11b": unicorn.x86_const.UC_X86_REG_R11B,
        "r12": unicorn.x86_const.UC_X86_REG_R12,
        "r12d": unicorn.x86_const.UC_X86_REG_R12D,
        "r12w": unicorn.x86_const.UC_X86_REG_R12W,
        "r12b": unicorn.x86_const.UC_X86_REG_R12B,
        "r13": unicorn.x86_const.UC_X86_REG_R13,
        "r13d": unicorn.x86_const.UC_X86_REG_R13D,
        "r13w": unicorn.x86_const.UC_X86_REG_R13W,
        "r13b": unicorn.x86_const.UC_X86_REG_R13B,
        "r14": unicorn.x86_const.UC_X86_REG_R14,
        "r14d": unicorn.x86_const.UC_X86_REG_R14D,
        "r14w": unicorn.x86_const.UC_X86_REG_R14W,
        "r14b": unicorn.x86_const.UC_X86_REG_R14B,
        "r15": unicorn.x86_const.UC_X86_REG_R15,
        "r15d": unicorn.x86_const.UC_X86_REG_R15D,
        "r15w": unicorn.x86_const.UC_X86_REG_R15W,
        "r15b": unicorn.x86_const.UC_X86_REG_R15B,
        "rsi": unicorn.x86_const.UC_X86_REG_RSI,
        "esi": unicorn.x86_const.UC_X86_REG_ESI,
        "si": unicorn.x86_const.UC_X86_REG_SI,
        "sil": unicorn.x86_const.UC_X86_REG_SIL,
        "rdi": unicorn.x86_const.UC_X86_REG_RDI,
        "edi": unicorn.x86_const.UC_X86_REG_EDI,
        "di": unicorn.x86_const.UC_X86_REG_DI,
        "dil": unicorn.x86_const.UC_X86_REG_DIL,
        "rbp": unicorn.x86_const.UC_X86_REG_RBP,
        "ebp": unicorn.x86_const.UC_X86_REG_EBP,
        "bp": unicorn.x86_const.UC_X86_REG_BP,
        "bpl": unicorn.x86_const.UC_X86_REG_BPL,
        "rsp": unicorn.x86_const.UC_X86_REG_RSP,
        "esp": unicorn.x86_const.UC_X86_REG_ESP,
        "sp": unicorn.x86_const.UC_X86_REG_SP,
        "spl": unicorn.x86_const.UC_X86_REG_SPL,
        "rip": unicorn.x86_const.UC_X86_REG_RIP,
        "eip": unicorn.x86_const.UC_X86_REG_EIP,
        "ip": unicorn.x86_const.UC_X86_REG_IP,
        "cs": unicorn.x86_const.UC_X86_REG_CS,
        "ds": unicorn.x86_const.UC_X86_REG_DS,
        "es": unicorn.x86_const.UC_X86_REG_ES,
        "fs": unicorn.x86_const.UC_X86_REG_FS,
        "gs": unicorn.x86_const.UC_X86_REG_GS,
        "rflags": unicorn.x86_const.UC_X86_REG_RFLAGS,
        "eflags": unicorn.x86_const.UC_X86_REG_EFLAGS,
        "flags": unicorn.x86_const.UC_X86_REG_FLAGS,
        "cr0": unicorn.x86_const.UC_X86_REG_CR0,
        "cr1": unicorn.x86_const.UC_X86_REG_CR1,
        "cr2": unicorn.x86_const.UC_X86_REG_CR2,
        "cr3": unicorn.x86_const.UC_X86_REG_CR3,
        "cr4": unicorn.x86_const.UC_X86_REG_CR4,
    }
