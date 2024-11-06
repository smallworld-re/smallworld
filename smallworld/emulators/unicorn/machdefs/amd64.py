import capstone
import unicorn

from ....platforms import Architecture, Byteorder
from .machdef import UnicornMachineDef


class AMD64MachineDef(UnicornMachineDef):
    """Unicorn machine definition for amd64"""

    byteorder = Byteorder.LITTLE

    uc_arch = unicorn.UC_ARCH_X86
    uc_mode = unicorn.UC_MODE_64

    cs_arch = capstone.CS_ARCH_X86
    cs_mode = capstone.CS_MODE_64

    pc_reg = "rip"

    def __init__(self):
        self._registers = {
            # *** General Purpose Registers ***
            "rax": (unicorn.x86_const.UC_X86_REG_RAX, "rax", 8, 0),
            "eax": (unicorn.x86_const.UC_X86_REG_EAX, "rax", 4, 0),
            "ax": (unicorn.x86_const.UC_X86_REG_AX, "rax", 2, 0),
            "al": (unicorn.x86_const.UC_X86_REG_AL, "rax", 1, 0),
            "ah": (unicorn.x86_const.UC_X86_REG_AH, "rax", 1, 1),
            "rbx": (unicorn.x86_const.UC_X86_REG_RBX, "rbx", 8, 0),
            "ebx": (unicorn.x86_const.UC_X86_REG_EBX, "rbx", 4, 0),
            "bx": (unicorn.x86_const.UC_X86_REG_BX, "rbx", 2, 0),
            "bl": (unicorn.x86_const.UC_X86_REG_BL, "rbx", 1, 0),
            "bh": (unicorn.x86_const.UC_X86_REG_BH, "rbx", 1, 1),
            "rcx": (unicorn.x86_const.UC_X86_REG_RCX, "rcx", 8, 0),
            "ecx": (unicorn.x86_const.UC_X86_REG_ECX, "rcx", 4, 0),
            "cx": (unicorn.x86_const.UC_X86_REG_CX, "rcx", 2, 0),
            "cl": (unicorn.x86_const.UC_X86_REG_CL, "rcx", 1, 0),
            "ch": (unicorn.x86_const.UC_X86_REG_CH, "rcx", 1, 1),
            "rdx": (unicorn.x86_const.UC_X86_REG_RDX, "rdx", 8, 0),
            "edx": (unicorn.x86_const.UC_X86_REG_EDX, "rdx", 4, 0),
            "dx": (unicorn.x86_const.UC_X86_REG_DX, "rdx", 2, 0),
            "dl": (unicorn.x86_const.UC_X86_REG_DL, "rdx", 1, 0),
            "dh": (unicorn.x86_const.UC_X86_REG_DH, "rdx", 1, 1),
            "r8": (unicorn.x86_const.UC_X86_REG_R8, "r8", 8, 0),
            "r8d": (unicorn.x86_const.UC_X86_REG_R8D, "r8", 4, 0),
            "r8w": (unicorn.x86_const.UC_X86_REG_R8W, "r8", 2, 0),
            "r8b": (unicorn.x86_const.UC_X86_REG_R8B, "r8", 1, 0),
            "r9": (unicorn.x86_const.UC_X86_REG_R9, "r9", 8, 0),
            "r9d": (unicorn.x86_const.UC_X86_REG_R9D, "r9", 4, 0),
            "r9w": (unicorn.x86_const.UC_X86_REG_R9W, "r9", 2, 0),
            "r9b": (unicorn.x86_const.UC_X86_REG_R9B, "r9", 1, 0),
            "r10": (unicorn.x86_const.UC_X86_REG_R10, "r10", 8, 0),
            "r10d": (unicorn.x86_const.UC_X86_REG_R10D, "r10", 4, 0),
            "r10w": (unicorn.x86_const.UC_X86_REG_R10W, "r10", 2, 0),
            "r10b": (unicorn.x86_const.UC_X86_REG_R10B, "r10", 1, 0),
            "r11": (unicorn.x86_const.UC_X86_REG_R11, "r11", 8, 0),
            "r11d": (unicorn.x86_const.UC_X86_REG_R11D, "r11", 4, 0),
            "r11w": (unicorn.x86_const.UC_X86_REG_R11W, "r11", 2, 0),
            "r11b": (unicorn.x86_const.UC_X86_REG_R11B, "r11", 1, 0),
            "r12": (unicorn.x86_const.UC_X86_REG_R12, "r12", 8, 0),
            "r12d": (unicorn.x86_const.UC_X86_REG_R12D, "r12", 4, 0),
            "r12w": (unicorn.x86_const.UC_X86_REG_R12W, "r12", 2, 0),
            "r12b": (unicorn.x86_const.UC_X86_REG_R12B, "r12", 1, 0),
            "r13": (unicorn.x86_const.UC_X86_REG_R13, "r13", 8, 0),
            "r13d": (unicorn.x86_const.UC_X86_REG_R13D, "r13", 4, 0),
            "r13w": (unicorn.x86_const.UC_X86_REG_R13W, "r13", 2, 0),
            "r13b": (unicorn.x86_const.UC_X86_REG_R13B, "r13", 1, 0),
            "r14": (unicorn.x86_const.UC_X86_REG_R14, "r14", 8, 0),
            "r14d": (unicorn.x86_const.UC_X86_REG_R14D, "r14", 4, 0),
            "r14w": (unicorn.x86_const.UC_X86_REG_R14W, "r14", 2, 0),
            "r14b": (unicorn.x86_const.UC_X86_REG_R14B, "r14", 1, 0),
            "r15": (unicorn.x86_const.UC_X86_REG_R15, "r15", 8, 0),
            "r15d": (unicorn.x86_const.UC_X86_REG_R15D, "r15", 4, 0),
            "r15w": (unicorn.x86_const.UC_X86_REG_R15W, "r15", 2, 0),
            "r15b": (unicorn.x86_const.UC_X86_REG_R15B, "r15", 1, 0),
            "rdi": (unicorn.x86_const.UC_X86_REG_RDI, "rdi", 8, 0),
            "edi": (unicorn.x86_const.UC_X86_REG_EDI, "rdi", 4, 0),
            "di": (unicorn.x86_const.UC_X86_REG_DI, "rdi", 2, 0),
            "dil": (unicorn.x86_const.UC_X86_REG_DIL, "rdi", 1, 0),
            "rsi": (unicorn.x86_const.UC_X86_REG_RSI, "rsi", 8, 0),
            "esi": (unicorn.x86_const.UC_X86_REG_ESI, "rsi", 4, 0),
            "si": (unicorn.x86_const.UC_X86_REG_SI, "rsi", 2, 0),
            "sil": (unicorn.x86_const.UC_X86_REG_SIL, "rsi", 1, 0),
            "rsp": (unicorn.x86_const.UC_X86_REG_RSP, "rsp", 8, 0),
            "esp": (unicorn.x86_const.UC_X86_REG_ESP, "rsp", 4, 0),
            "sp": (unicorn.x86_const.UC_X86_REG_SP, "rsp", 2, 0),
            "spl": (unicorn.x86_const.UC_X86_REG_SPL, "rsp", 1, 0),
            "rbp": (unicorn.x86_const.UC_X86_REG_RBP, "rbp", 8, 0),
            "ebp": (unicorn.x86_const.UC_X86_REG_EBP, "rbp", 4, 0),
            "bp": (unicorn.x86_const.UC_X86_REG_BP, "rbp", 2, 0),
            "bpl": (unicorn.x86_const.UC_X86_REG_BPL, "rbp", 1, 0),
            # *** Instruction Pointer ***
            "rip": (unicorn.x86_const.UC_X86_REG_RIP, "rip", 8, 0),
            "eip": (unicorn.x86_const.UC_X86_REG_EIP, "rip", 4, 0),
            "ip": (unicorn.x86_const.UC_X86_REG_IP, "rip", 2, 0),
            # *** Flags register ***
            "rflags": (unicorn.x86_const.UC_X86_REG_RFLAGS, "rflags", 8, 0),
            "eflags": (unicorn.x86_const.UC_X86_REG_EFLAGS, "rflags", 4, 0),
            "flags": (unicorn.x86_const.UC_X86_REG_FLAGS, "rflags", 2, 0),
            # *** Segment Registers ***
            "cs": (unicorn.x86_const.UC_X86_REG_CS, "cs", 2, 0),
            "ds": (unicorn.x86_const.UC_X86_REG_DS, "ds", 2, 0),
            "es": (unicorn.x86_const.UC_X86_REG_ES, "es", 2, 0),
            "fs": (unicorn.x86_const.UC_X86_REG_FS, "fs", 2, 0),
            "gs": (unicorn.x86_const.UC_X86_REG_GS, "gs", 2, 0),
            # *** Control Registers ***
            "cr0": (unicorn.x86_const.UC_X86_REG_CR0, "cr0", 8, 0),
            "cr1": (unicorn.x86_const.UC_X86_REG_CR1, "cr1", 8, 0),
            "cr2": (unicorn.x86_const.UC_X86_REG_CR2, "cr2", 8, 0),
            "cr3": (unicorn.x86_const.UC_X86_REG_CR3, "cr3", 8, 0),
            "cr4": (unicorn.x86_const.UC_X86_REG_CR4, "cr4", 8, 0),
            "cr8": (unicorn.x86_const.UC_X86_REG_INVALID, "cr8", 8, 0),
            # *** Debug Registers ***
            "dr0": (unicorn.x86_const.UC_X86_REG_DR0, "dr0", 8, 0),
            "dr1": (unicorn.x86_const.UC_X86_REG_DR1, "dr1", 8, 0),
            "dr2": (unicorn.x86_const.UC_X86_REG_DR2, "dr2", 8, 0),
            "dr3": (unicorn.x86_const.UC_X86_REG_DR3, "dr3", 8, 0),
            "dr6": (unicorn.x86_const.UC_X86_REG_DR6, "dr6", 8, 0),
            "dr7": (unicorn.x86_const.UC_X86_REG_DR7, "dr7", 8, 0),
            "dr8": (unicorn.x86_const.UC_X86_REG_INVALID, "dr8", 8, 0),
            "dr9": (unicorn.x86_const.UC_X86_REG_INVALID, "dr9", 8, 0),
            "dr10": (unicorn.x86_const.UC_X86_REG_INVALID, "dr10", 8, 0),
            "dr11": (unicorn.x86_const.UC_X86_REG_INVALID, "dr11", 8, 0),
            "dr12": (unicorn.x86_const.UC_X86_REG_INVALID, "dr12", 8, 0),
            "dr13": (unicorn.x86_const.UC_X86_REG_INVALID, "dr13", 8, 0),
            "dr14": (unicorn.x86_const.UC_X86_REG_INVALID, "dr14", 8, 0),
            "dr15": (unicorn.x86_const.UC_X86_REG_INVALID, "dr15", 8, 0),
            # *** Descriptor Table Registers ***
            "gdtr": (unicorn.x86_const.UC_X86_REG_GDTR, "gdtr", 10, 0),
            "idtr": (unicorn.x86_const.UC_X86_REG_IDTR, "idtr", 10, 0),
            "ldtr": (unicorn.x86_const.UC_X86_REG_LDTR, "ldtr", 10, 0),
            # *** Task Register ***
            "tr": (unicorn.x86_const.UC_X86_REG_TR, "tr", 2, 0),
            # *** x87 registers ***
            # NOTE: x87 is supported by Unicorn, but not by SmallWorld.
            # Values are represented as tuples (exponent: int, mantissa: int).
            # If you need x87 support, open a ticket.
            "fpr0": (unicorn.x86_const.UC_X86_REG_INVALID, "fpr0", 10, 0),
            "fpr1": (unicorn.x86_const.UC_X86_REG_INVALID, "fpr1", 10, 0),
            "fpr2": (unicorn.x86_const.UC_X86_REG_INVALID, "fpr2", 10, 0),
            "fpr3": (unicorn.x86_const.UC_X86_REG_INVALID, "fpr3", 10, 0),
            "fpr4": (unicorn.x86_const.UC_X86_REG_INVALID, "fpr4", 10, 0),
            "fpr5": (unicorn.x86_const.UC_X86_REG_INVALID, "fpr5", 10, 0),
            "fpr6": (unicorn.x86_const.UC_X86_REG_INVALID, "fpr6", 10, 0),
            "fpr7": (unicorn.x86_const.UC_X86_REG_INVALID, "fpr7", 10, 0),
            # x87 Control Register
            "fctrl": (unicorn.x86_const.UC_X86_REG_FPCW, "fctrl", 2, 0),
            # x87 Status Register
            "fstat": (unicorn.x86_const.UC_X86_REG_FPCW, "fstat", 2, 0),
            # x87 Tag Register
            "ftag": (unicorn.x86_const.UC_X86_REG_FPTAG, "ftag", 2, 0),
            # x87 Last Instruction Register
            "fip": (unicorn.x86_const.UC_X86_REG_FIP, "fip", 8, 0),
            # x87 Last Operand Pointer
            "fdp": (unicorn.x86_const.UC_X86_REG_FDP, "fdp", 8, 0),
            # x87 Last Opcode
            "fop": (unicorn.x86_const.UC_X86_REG_FOP, "fop", 2, 0),
            # NOTE: Docs disagree on the format of fip and fdp.
            # One source describes them as 48-bit offset-plus-segment,
            # the other describes them as 64-bit.
            # There may also be separate segment registers.
            # If you care about the x87 debug info, please feel free to update.
            # *** MMX Registers ***
            # NOTE: The MMX registers are aliases for the low 8 bytes of the x87 registers.
            # The two subsystems cannot be used simultaneously.
            "mm0": (unicorn.x86_const.UC_X86_REG_MM0, "fpr0", 8, 0),
            "mm1": (unicorn.x86_const.UC_X86_REG_MM1, "fpr1", 8, 0),
            "mm2": (unicorn.x86_const.UC_X86_REG_MM2, "fpr2", 8, 0),
            "mm3": (unicorn.x86_const.UC_X86_REG_MM3, "fpr3", 8, 0),
            "mm4": (unicorn.x86_const.UC_X86_REG_MM4, "fpr4", 8, 0),
            "mm5": (unicorn.x86_const.UC_X86_REG_MM5, "fpr5", 8, 0),
            "mm6": (unicorn.x86_const.UC_X86_REG_MM6, "fpr6", 8, 0),
            "mm7": (unicorn.x86_const.UC_X86_REG_MM7, "fpr7", 8, 0),
        }


class AMD64AVX2MachineDef(AMD64MachineDef):
    arch = Architecture.X86_64

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # *** SSE/AVX registers ***
                "ymm0": (unicorn.x86_const.UC_X86_REG_YMM0, "ymm0", 32, 0),
                "xmm0": (unicorn.x86_const.UC_X86_REG_XMM0, "ymm0", 16, 0),
                "ymm1": (unicorn.x86_const.UC_X86_REG_YMM1, "ymm1", 32, 0),
                "xmm1": (unicorn.x86_const.UC_X86_REG_XMM1, "ymm1", 16, 0),
                "ymm2": (unicorn.x86_const.UC_X86_REG_YMM2, "ymm2", 32, 0),
                "xmm2": (unicorn.x86_const.UC_X86_REG_XMM2, "ymm2", 16, 0),
                "ymm3": (unicorn.x86_const.UC_X86_REG_YMM3, "ymm3", 32, 0),
                "xmm3": (unicorn.x86_const.UC_X86_REG_XMM3, "ymm3", 16, 0),
                "ymm4": (unicorn.x86_const.UC_X86_REG_YMM4, "ymm4", 32, 0),
                "xmm4": (unicorn.x86_const.UC_X86_REG_XMM4, "ymm4", 16, 0),
                "ymm5": (unicorn.x86_const.UC_X86_REG_YMM5, "ymm5", 32, 0),
                "xmm5": (unicorn.x86_const.UC_X86_REG_XMM5, "ymm5", 16, 0),
                "ymm6": (unicorn.x86_const.UC_X86_REG_YMM6, "ymm6", 32, 0),
                "xmm6": (unicorn.x86_const.UC_X86_REG_XMM6, "ymm6", 16, 0),
                "ymm7": (unicorn.x86_const.UC_X86_REG_YMM7, "ymm7", 32, 0),
                "xmm7": (unicorn.x86_const.UC_X86_REG_XMM7, "ymm7", 16, 0),
                "ymm8": (unicorn.x86_const.UC_X86_REG_YMM8, "ymm8", 32, 0),
                "xmm8": (unicorn.x86_const.UC_X86_REG_XMM8, "ymm8", 16, 0),
                "ymm9": (unicorn.x86_const.UC_X86_REG_YMM9, "ymm9", 32, 0),
                "xmm9": (unicorn.x86_const.UC_X86_REG_XMM9, "ymm9", 16, 0),
                "ymm10": (unicorn.x86_const.UC_X86_REG_YMM10, "ymm10", 32, 0),
                "xmm10": (unicorn.x86_const.UC_X86_REG_XMM10, "ymm10", 16, 0),
                "ymm11": (unicorn.x86_const.UC_X86_REG_YMM11, "ymm11", 32, 0),
                "xmm11": (unicorn.x86_const.UC_X86_REG_XMM11, "ymm11", 16, 0),
                "ymm12": (unicorn.x86_const.UC_X86_REG_YMM12, "ymm12", 32, 0),
                "xmm12": (unicorn.x86_const.UC_X86_REG_XMM12, "ymm12", 16, 0),
                "ymm13": (unicorn.x86_const.UC_X86_REG_YMM13, "ymm13", 32, 0),
                "xmm13": (unicorn.x86_const.UC_X86_REG_XMM13, "ymm13", 16, 0),
                "ymm14": (unicorn.x86_const.UC_X86_REG_YMM14, "ymm14", 32, 0),
                "xmm14": (unicorn.x86_const.UC_X86_REG_XMM14, "ymm14", 16, 0),
                "ymm15": (unicorn.x86_const.UC_X86_REG_YMM15, "ymm15", 32, 0),
                "xmm15": (unicorn.x86_const.UC_X86_REG_XMM15, "ymm15", 16, 0),
            }
        )


class AMD64AVX512MachineDef(AMD64MachineDef):
    arch = Architecture.X86_64_AVX512

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # *** SSE/AVX registers ***
                "zmm0": (unicorn.x86_const.UC_X86_REG_ZMM0, "zmm0", 64, 0),
                "ymm0": (unicorn.x86_const.UC_X86_REG_YMM0, "zmm0", 32, 0),
                "xmm0": (unicorn.x86_const.UC_X86_REG_XMM0, "zmm0", 16, 0),
                "zmm1": (unicorn.x86_const.UC_X86_REG_ZMM1, "zmm1", 64, 0),
                "ymm1": (unicorn.x86_const.UC_X86_REG_YMM1, "zmm1", 32, 0),
                "xmm1": (unicorn.x86_const.UC_X86_REG_XMM1, "zmm1", 16, 0),
                "zmm2": (unicorn.x86_const.UC_X86_REG_ZMM2, "zmm2", 64, 0),
                "ymm2": (unicorn.x86_const.UC_X86_REG_YMM2, "zmm2", 32, 0),
                "xmm2": (unicorn.x86_const.UC_X86_REG_XMM2, "zmm2", 16, 0),
                "zmm3": (unicorn.x86_const.UC_X86_REG_ZMM3, "zmm3", 64, 0),
                "ymm3": (unicorn.x86_const.UC_X86_REG_YMM3, "zmm3", 32, 0),
                "xmm3": (unicorn.x86_const.UC_X86_REG_XMM3, "zmm3", 16, 0),
                "zmm4": (unicorn.x86_const.UC_X86_REG_ZMM4, "zmm4", 64, 0),
                "ymm4": (unicorn.x86_const.UC_X86_REG_YMM4, "zmm4", 32, 0),
                "xmm4": (unicorn.x86_const.UC_X86_REG_XMM4, "zmm4", 16, 0),
                "zmm5": (unicorn.x86_const.UC_X86_REG_ZMM5, "zmm5", 64, 0),
                "ymm5": (unicorn.x86_const.UC_X86_REG_YMM5, "zmm5", 32, 0),
                "xmm5": (unicorn.x86_const.UC_X86_REG_XMM5, "zmm5", 16, 0),
                "zmm6": (unicorn.x86_const.UC_X86_REG_ZMM6, "zmm6", 64, 0),
                "ymm6": (unicorn.x86_const.UC_X86_REG_YMM6, "zmm6", 32, 0),
                "xmm6": (unicorn.x86_const.UC_X86_REG_XMM6, "zmm6", 16, 0),
                "zmm7": (unicorn.x86_const.UC_X86_REG_ZMM7, "zmm7", 64, 0),
                "ymm7": (unicorn.x86_const.UC_X86_REG_YMM7, "zmm7", 32, 0),
                "xmm7": (unicorn.x86_const.UC_X86_REG_XMM7, "zmm7", 16, 0),
                "zmm8": (unicorn.x86_const.UC_X86_REG_ZMM8, "zmm8", 64, 0),
                "ymm8": (unicorn.x86_const.UC_X86_REG_YMM8, "zmm8", 32, 0),
                "xmm8": (unicorn.x86_const.UC_X86_REG_XMM8, "zmm8", 16, 0),
                "zmm9": (unicorn.x86_const.UC_X86_REG_ZMM9, "zmm9", 64, 0),
                "ymm9": (unicorn.x86_const.UC_X86_REG_YMM9, "zmm9", 32, 0),
                "xmm9": (unicorn.x86_const.UC_X86_REG_XMM9, "zmm9", 16, 0),
                "zmm10": (unicorn.x86_const.UC_X86_REG_ZMM10, "zmm10", 64, 0),
                "ymm10": (unicorn.x86_const.UC_X86_REG_YMM10, "zmm10", 32, 0),
                "xmm10": (unicorn.x86_const.UC_X86_REG_XMM10, "zmm10", 16, 0),
                "zmm11": (unicorn.x86_const.UC_X86_REG_ZMM11, "zmm11", 64, 0),
                "ymm11": (unicorn.x86_const.UC_X86_REG_YMM11, "zmm11", 32, 0),
                "xmm11": (unicorn.x86_const.UC_X86_REG_XMM11, "zmm11", 16, 0),
                "zmm12": (unicorn.x86_const.UC_X86_REG_ZMM12, "zmm12", 64, 0),
                "ymm12": (unicorn.x86_const.UC_X86_REG_YMM12, "zmm12", 32, 0),
                "xmm12": (unicorn.x86_const.UC_X86_REG_XMM12, "zmm12", 16, 0),
                "zmm13": (unicorn.x86_const.UC_X86_REG_ZMM13, "zmm13", 64, 0),
                "ymm13": (unicorn.x86_const.UC_X86_REG_YMM13, "zmm13", 32, 0),
                "xmm13": (unicorn.x86_const.UC_X86_REG_XMM13, "zmm13", 16, 0),
                "zmm14": (unicorn.x86_const.UC_X86_REG_ZMM14, "zmm14", 64, 0),
                "ymm14": (unicorn.x86_const.UC_X86_REG_YMM14, "zmm14", 32, 0),
                "xmm14": (unicorn.x86_const.UC_X86_REG_XMM14, "zmm14", 16, 0),
                "zmm15": (unicorn.x86_const.UC_X86_REG_ZMM15, "zmm15", 64, 0),
                "ymm15": (unicorn.x86_const.UC_X86_REG_YMM15, "zmm15", 32, 0),
                "xmm15": (unicorn.x86_const.UC_X86_REG_XMM15, "zmm15", 16, 0),
                "zmm16": (unicorn.x86_const.UC_X86_REG_ZMM16, "zmm16", 64, 0),
                "ymm16": (unicorn.x86_const.UC_X86_REG_YMM16, "zmm16", 32, 0),
                "xmm16": (unicorn.x86_const.UC_X86_REG_XMM16, "zmm16", 16, 0),
                "zmm17": (unicorn.x86_const.UC_X86_REG_ZMM17, "zmm17", 64, 0),
                "ymm17": (unicorn.x86_const.UC_X86_REG_YMM17, "zmm17", 32, 0),
                "xmm17": (unicorn.x86_const.UC_X86_REG_XMM17, "zmm17", 16, 0),
                "zmm18": (unicorn.x86_const.UC_X86_REG_ZMM18, "zmm18", 64, 0),
                "ymm18": (unicorn.x86_const.UC_X86_REG_YMM18, "zmm18", 32, 0),
                "xmm18": (unicorn.x86_const.UC_X86_REG_XMM18, "zmm18", 16, 0),
                "zmm19": (unicorn.x86_const.UC_X86_REG_ZMM19, "zmm19", 64, 0),
                "ymm19": (unicorn.x86_const.UC_X86_REG_YMM19, "zmm19", 32, 0),
                "xmm19": (unicorn.x86_const.UC_X86_REG_XMM19, "zmm19", 16, 0),
                "zmm20": (unicorn.x86_const.UC_X86_REG_ZMM20, "zmm20", 64, 0),
                "ymm20": (unicorn.x86_const.UC_X86_REG_YMM20, "zmm20", 32, 0),
                "xmm20": (unicorn.x86_const.UC_X86_REG_XMM20, "zmm20", 16, 0),
                "zmm21": (unicorn.x86_const.UC_X86_REG_ZMM21, "zmm21", 64, 0),
                "ymm21": (unicorn.x86_const.UC_X86_REG_YMM21, "zmm21", 32, 0),
                "xmm21": (unicorn.x86_const.UC_X86_REG_XMM21, "zmm21", 16, 0),
                "zmm22": (unicorn.x86_const.UC_X86_REG_ZMM22, "zmm22", 64, 0),
                "ymm22": (unicorn.x86_const.UC_X86_REG_YMM22, "zmm22", 32, 0),
                "xmm22": (unicorn.x86_const.UC_X86_REG_XMM22, "zmm22", 16, 0),
                "zmm23": (unicorn.x86_const.UC_X86_REG_ZMM23, "zmm23", 64, 0),
                "ymm23": (unicorn.x86_const.UC_X86_REG_YMM23, "zmm23", 32, 0),
                "xmm23": (unicorn.x86_const.UC_X86_REG_XMM23, "zmm23", 16, 0),
                "zmm24": (unicorn.x86_const.UC_X86_REG_ZMM24, "zmm24", 64, 0),
                "ymm24": (unicorn.x86_const.UC_X86_REG_YMM24, "zmm24", 32, 0),
                "xmm24": (unicorn.x86_const.UC_X86_REG_XMM24, "zmm24", 16, 0),
                "zmm25": (unicorn.x86_const.UC_X86_REG_ZMM25, "zmm25", 64, 0),
                "ymm25": (unicorn.x86_const.UC_X86_REG_YMM25, "zmm25", 32, 0),
                "xmm25": (unicorn.x86_const.UC_X86_REG_XMM25, "zmm25", 16, 0),
                "zmm26": (unicorn.x86_const.UC_X86_REG_ZMM26, "zmm26", 64, 0),
                "ymm26": (unicorn.x86_const.UC_X86_REG_YMM26, "zmm26", 32, 0),
                "xmm26": (unicorn.x86_const.UC_X86_REG_XMM26, "zmm26", 16, 0),
                "zmm27": (unicorn.x86_const.UC_X86_REG_ZMM27, "zmm27", 64, 0),
                "ymm27": (unicorn.x86_const.UC_X86_REG_YMM27, "zmm27", 32, 0),
                "xmm27": (unicorn.x86_const.UC_X86_REG_XMM27, "zmm27", 16, 0),
                "zmm28": (unicorn.x86_const.UC_X86_REG_ZMM28, "zmm28", 64, 0),
                "ymm28": (unicorn.x86_const.UC_X86_REG_YMM28, "zmm28", 32, 0),
                "xmm28": (unicorn.x86_const.UC_X86_REG_XMM28, "zmm28", 16, 0),
                "zmm29": (unicorn.x86_const.UC_X86_REG_ZMM29, "zmm29", 64, 0),
                "ymm29": (unicorn.x86_const.UC_X86_REG_YMM29, "zmm29", 32, 0),
                "xmm29": (unicorn.x86_const.UC_X86_REG_XMM29, "zmm29", 16, 0),
                "zmm30": (unicorn.x86_const.UC_X86_REG_ZMM30, "zmm30", 64, 0),
                "ymm30": (unicorn.x86_const.UC_X86_REG_YMM30, "zmm30", 32, 0),
                "xmm30": (unicorn.x86_const.UC_X86_REG_XMM30, "zmm30", 16, 0),
                "zmm31": (unicorn.x86_const.UC_X86_REG_ZMM31, "zmm31", 64, 0),
                "ymm31": (unicorn.x86_const.UC_X86_REG_YMM31, "zmm31", 32, 0),
                "xmm31": (unicorn.x86_const.UC_X86_REG_XMM31, "zmm31", 16, 0),
            }
        )
