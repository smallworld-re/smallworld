import unicorn

from ....platforms import Architecture, Byteorder
from .machdef import UnicornMachineDef


class AMD64MachineDef(UnicornMachineDef):
    """Unicorn machine definition for amd64"""

    byteorder = Byteorder.LITTLE

    uc_arch = unicorn.UC_ARCH_X86
    uc_mode = unicorn.UC_MODE_64

    def __init__(self):
        self._registers = {
            # *** General Purpose Registers ***
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
            "rdi": unicorn.x86_const.UC_X86_REG_RDI,
            "edi": unicorn.x86_const.UC_X86_REG_EDI,
            "di": unicorn.x86_const.UC_X86_REG_DI,
            "dil": unicorn.x86_const.UC_X86_REG_DIL,
            "rsi": unicorn.x86_const.UC_X86_REG_RSI,
            "esi": unicorn.x86_const.UC_X86_REG_ESI,
            "si": unicorn.x86_const.UC_X86_REG_SI,
            "sil": unicorn.x86_const.UC_X86_REG_SIL,
            "rsp": unicorn.x86_const.UC_X86_REG_RSP,
            "esp": unicorn.x86_const.UC_X86_REG_ESP,
            "sp": unicorn.x86_const.UC_X86_REG_SP,
            "spl": unicorn.x86_const.UC_X86_REG_SPL,
            "rbp": unicorn.x86_const.UC_X86_REG_RBP,
            "ebp": unicorn.x86_const.UC_X86_REG_EBP,
            "bp": unicorn.x86_const.UC_X86_REG_BP,
            "bpl": unicorn.x86_const.UC_X86_REG_BPL,
            # *** Instruction Pointer ***
            "rip": unicorn.x86_const.UC_X86_REG_RIP,
            "eip": unicorn.x86_const.UC_X86_REG_EIP,
            "ip": unicorn.x86_const.UC_X86_REG_IP,
            # *** Flags register ***
            "rflags": unicorn.x86_const.UC_X86_REG_RFLAGS,
            "eflags": unicorn.x86_const.UC_X86_REG_EFLAGS,
            "flags": unicorn.x86_const.UC_X86_REG_FLAGS,
            # *** Segment Registers ***
            "cs": unicorn.x86_const.UC_X86_REG_CS,
            "ds": unicorn.x86_const.UC_X86_REG_DS,
            "es": unicorn.x86_const.UC_X86_REG_ES,
            "fs": unicorn.x86_const.UC_X86_REG_FS,
            "gs": unicorn.x86_const.UC_X86_REG_GS,
            # *** Control Registers ***
            "cr0": unicorn.x86_const.UC_X86_REG_CR0,
            "cr1": unicorn.x86_const.UC_X86_REG_CR1,
            "cr2": unicorn.x86_const.UC_X86_REG_CR2,
            "cr3": unicorn.x86_const.UC_X86_REG_CR3,
            "cr4": unicorn.x86_const.UC_X86_REG_CR4,
            "cr8": unicorn.x86_const.UC_X86_REG_INVALID,
            # *** Debug Registers ***
            "dr0": unicorn.x86_const.UC_X86_REG_DR0,
            "dr1": unicorn.x86_const.UC_X86_REG_DR1,
            "dr2": unicorn.x86_const.UC_X86_REG_DR2,
            "dr3": unicorn.x86_const.UC_X86_REG_DR3,
            "dr6": unicorn.x86_const.UC_X86_REG_DR6,
            "dr7": unicorn.x86_const.UC_X86_REG_DR7,
            "dr8": unicorn.x86_const.UC_X86_REG_INVALID,
            "dr9": unicorn.x86_const.UC_X86_REG_INVALID,
            "dr10": unicorn.x86_const.UC_X86_REG_INVALID,
            "dr11": unicorn.x86_const.UC_X86_REG_INVALID,
            "dr12": unicorn.x86_const.UC_X86_REG_INVALID,
            "dr13": unicorn.x86_const.UC_X86_REG_INVALID,
            "dr14": unicorn.x86_const.UC_X86_REG_INVALID,
            "dr15": unicorn.x86_const.UC_X86_REG_INVALID,
            # *** Descriptor Table Registers ***
            "gdtr": unicorn.x86_const.UC_X86_REG_GDTR,
            "idtr": unicorn.x86_const.UC_X86_REG_IDTR,
            "ldtr": unicorn.x86_const.UC_X86_REG_LDTR,
            # *** Task Register ***
            "tr": unicorn.x86_const.UC_X86_REG_TR,
            # *** x87 registers ***
            # NOTE: x87 is supported by Unicorn, but not by SmallWorld.
            # Values are represented as tuples (exponent: int, mantissa: int).
            # If you need x87 support, open a ticket.
            "fpr0": unicorn.x86_const.UC_X86_REG_INVALID,
            "fpr1": unicorn.x86_const.UC_X86_REG_INVALID,
            "fpr2": unicorn.x86_const.UC_X86_REG_INVALID,
            "fpr3": unicorn.x86_const.UC_X86_REG_INVALID,
            "fpr4": unicorn.x86_const.UC_X86_REG_INVALID,
            "fpr5": unicorn.x86_const.UC_X86_REG_INVALID,
            "fpr6": unicorn.x86_const.UC_X86_REG_INVALID,
            "fpr7": unicorn.x86_const.UC_X86_REG_INVALID,
            # x87 Control Register
            "fctrl": unicorn.x86_const.UC_X86_REG_FPCW,
            # x87 Status Register
            "fstat": unicorn.x86_const.UC_X86_REG_FPCW,
            # x87 Tag Register
            "ftag": unicorn.x86_const.UC_X86_REG_FPTAG,
            # x87 Last Instruction Register
            "fip": unicorn.x86_const.UC_X86_REG_FIP,
            # x87 Last Operand Pointer
            "fdp": unicorn.x86_const.UC_X86_REG_FDP,
            # x87 Last Opcode
            "fop": unicorn.x86_const.UC_X86_REG_FOP,
            # NOTE: Docs disagree on the format of fip and fdp.
            # One source describes them as 48-bit offset-plus-segment,
            # the other describes them as 64-bit.
            # There may also be separate segment registers.
            # If you care about the x87 debug info, please feel free to update.
            # *** MMX Registers ***
            # NOTE: The MMX registers are aliases for the low 8 bytes of the x87 registers.
            # The two subsystems cannot be used simultaneously.
            "mm0": unicorn.x86_const.UC_X86_REG_MM0,
            "mm1": unicorn.x86_const.UC_X86_REG_MM1,
            "mm2": unicorn.x86_const.UC_X86_REG_MM2,
            "mm3": unicorn.x86_const.UC_X86_REG_MM3,
            "mm4": unicorn.x86_const.UC_X86_REG_MM4,
            "mm5": unicorn.x86_const.UC_X86_REG_MM5,
            "mm6": unicorn.x86_const.UC_X86_REG_MM6,
            "mm7": unicorn.x86_const.UC_X86_REG_MM7,
        }


class AMD64AVX2MachineDef(AMD64MachineDef):
    arch = Architecture.X86_64

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # *** SSE/AVX registers ***
                "ymm0": unicorn.x86_const.UC_X86_REG_YMM0,
                "xmm0": unicorn.x86_const.UC_X86_REG_XMM0,
                "ymm1": unicorn.x86_const.UC_X86_REG_YMM1,
                "xmm1": unicorn.x86_const.UC_X86_REG_XMM1,
                "ymm2": unicorn.x86_const.UC_X86_REG_YMM2,
                "xmm2": unicorn.x86_const.UC_X86_REG_XMM2,
                "ymm3": unicorn.x86_const.UC_X86_REG_YMM3,
                "xmm3": unicorn.x86_const.UC_X86_REG_XMM3,
                "ymm4": unicorn.x86_const.UC_X86_REG_YMM4,
                "xmm4": unicorn.x86_const.UC_X86_REG_XMM4,
                "ymm5": unicorn.x86_const.UC_X86_REG_YMM5,
                "xmm5": unicorn.x86_const.UC_X86_REG_XMM5,
                "ymm6": unicorn.x86_const.UC_X86_REG_YMM6,
                "xmm6": unicorn.x86_const.UC_X86_REG_XMM6,
                "ymm7": unicorn.x86_const.UC_X86_REG_YMM7,
                "xmm7": unicorn.x86_const.UC_X86_REG_XMM7,
                "ymm8": unicorn.x86_const.UC_X86_REG_YMM8,
                "xmm8": unicorn.x86_const.UC_X86_REG_XMM8,
                "ymm9": unicorn.x86_const.UC_X86_REG_YMM9,
                "xmm9": unicorn.x86_const.UC_X86_REG_XMM9,
                "ymm10": unicorn.x86_const.UC_X86_REG_YMM10,
                "xmm10": unicorn.x86_const.UC_X86_REG_XMM10,
                "ymm11": unicorn.x86_const.UC_X86_REG_YMM11,
                "xmm11": unicorn.x86_const.UC_X86_REG_XMM11,
                "ymm12": unicorn.x86_const.UC_X86_REG_YMM12,
                "xmm12": unicorn.x86_const.UC_X86_REG_XMM12,
                "ymm13": unicorn.x86_const.UC_X86_REG_YMM13,
                "xmm13": unicorn.x86_const.UC_X86_REG_XMM13,
                "ymm14": unicorn.x86_const.UC_X86_REG_YMM14,
                "xmm14": unicorn.x86_const.UC_X86_REG_XMM14,
                "ymm15": unicorn.x86_const.UC_X86_REG_YMM15,
                "xmm15": unicorn.x86_const.UC_X86_REG_XMM15,
            }
        )


class AMD64AVX512MachineDef(AMD64MachineDef):
    arch = Architecture.X86_64_AVX512

    def __init__(self):
        super().__init__()
        self._registers.update(
            {
                # *** SSE/AVX registers ***
                "zmm0": unicorn.x86_const.UC_X86_REG_ZMM0,
                "ymm0": unicorn.x86_const.UC_X86_REG_YMM0,
                "xmm0": unicorn.x86_const.UC_X86_REG_XMM0,
                "zmm1": unicorn.x86_const.UC_X86_REG_ZMM1,
                "ymm1": unicorn.x86_const.UC_X86_REG_YMM1,
                "xmm1": unicorn.x86_const.UC_X86_REG_XMM1,
                "zmm2": unicorn.x86_const.UC_X86_REG_ZMM2,
                "ymm2": unicorn.x86_const.UC_X86_REG_YMM2,
                "xmm2": unicorn.x86_const.UC_X86_REG_XMM2,
                "zmm3": unicorn.x86_const.UC_X86_REG_ZMM3,
                "ymm3": unicorn.x86_const.UC_X86_REG_YMM3,
                "xmm3": unicorn.x86_const.UC_X86_REG_XMM3,
                "zmm4": unicorn.x86_const.UC_X86_REG_ZMM4,
                "ymm4": unicorn.x86_const.UC_X86_REG_YMM4,
                "xmm4": unicorn.x86_const.UC_X86_REG_XMM4,
                "zmm5": unicorn.x86_const.UC_X86_REG_ZMM5,
                "ymm5": unicorn.x86_const.UC_X86_REG_YMM5,
                "xmm5": unicorn.x86_const.UC_X86_REG_XMM5,
                "zmm6": unicorn.x86_const.UC_X86_REG_ZMM6,
                "ymm6": unicorn.x86_const.UC_X86_REG_YMM6,
                "xmm6": unicorn.x86_const.UC_X86_REG_XMM6,
                "zmm7": unicorn.x86_const.UC_X86_REG_ZMM7,
                "ymm7": unicorn.x86_const.UC_X86_REG_YMM7,
                "xmm7": unicorn.x86_const.UC_X86_REG_XMM7,
                "zmm8": unicorn.x86_const.UC_X86_REG_ZMM8,
                "ymm8": unicorn.x86_const.UC_X86_REG_YMM8,
                "xmm8": unicorn.x86_const.UC_X86_REG_XMM8,
                "zmm9": unicorn.x86_const.UC_X86_REG_ZMM9,
                "ymm9": unicorn.x86_const.UC_X86_REG_YMM9,
                "xmm9": unicorn.x86_const.UC_X86_REG_XMM9,
                "zmm10": unicorn.x86_const.UC_X86_REG_ZMM10,
                "ymm10": unicorn.x86_const.UC_X86_REG_YMM10,
                "xmm10": unicorn.x86_const.UC_X86_REG_XMM10,
                "zmm11": unicorn.x86_const.UC_X86_REG_ZMM11,
                "ymm11": unicorn.x86_const.UC_X86_REG_YMM11,
                "xmm11": unicorn.x86_const.UC_X86_REG_XMM11,
                "zmm12": unicorn.x86_const.UC_X86_REG_ZMM12,
                "ymm12": unicorn.x86_const.UC_X86_REG_YMM12,
                "xmm12": unicorn.x86_const.UC_X86_REG_XMM12,
                "zmm13": unicorn.x86_const.UC_X86_REG_ZMM13,
                "ymm13": unicorn.x86_const.UC_X86_REG_YMM13,
                "xmm13": unicorn.x86_const.UC_X86_REG_XMM13,
                "zmm14": unicorn.x86_const.UC_X86_REG_ZMM14,
                "ymm14": unicorn.x86_const.UC_X86_REG_YMM14,
                "xmm14": unicorn.x86_const.UC_X86_REG_XMM14,
                "zmm15": unicorn.x86_const.UC_X86_REG_ZMM15,
                "ymm15": unicorn.x86_const.UC_X86_REG_YMM15,
                "xmm15": unicorn.x86_const.UC_X86_REG_XMM15,
                "zmm16": unicorn.x86_const.UC_X86_REG_ZMM16,
                "ymm16": unicorn.x86_const.UC_X86_REG_YMM16,
                "xmm16": unicorn.x86_const.UC_X86_REG_XMM16,
                "zmm17": unicorn.x86_const.UC_X86_REG_ZMM17,
                "ymm17": unicorn.x86_const.UC_X86_REG_YMM17,
                "xmm17": unicorn.x86_const.UC_X86_REG_XMM17,
                "zmm18": unicorn.x86_const.UC_X86_REG_ZMM18,
                "ymm18": unicorn.x86_const.UC_X86_REG_YMM18,
                "xmm18": unicorn.x86_const.UC_X86_REG_XMM18,
                "zmm19": unicorn.x86_const.UC_X86_REG_ZMM19,
                "ymm19": unicorn.x86_const.UC_X86_REG_YMM19,
                "xmm19": unicorn.x86_const.UC_X86_REG_XMM19,
                "zmm20": unicorn.x86_const.UC_X86_REG_ZMM20,
                "ymm20": unicorn.x86_const.UC_X86_REG_YMM20,
                "xmm20": unicorn.x86_const.UC_X86_REG_XMM20,
                "zmm21": unicorn.x86_const.UC_X86_REG_ZMM21,
                "ymm21": unicorn.x86_const.UC_X86_REG_YMM21,
                "xmm21": unicorn.x86_const.UC_X86_REG_XMM21,
                "zmm22": unicorn.x86_const.UC_X86_REG_ZMM22,
                "ymm22": unicorn.x86_const.UC_X86_REG_YMM22,
                "xmm22": unicorn.x86_const.UC_X86_REG_XMM22,
                "zmm23": unicorn.x86_const.UC_X86_REG_ZMM23,
                "ymm23": unicorn.x86_const.UC_X86_REG_YMM23,
                "xmm23": unicorn.x86_const.UC_X86_REG_XMM23,
                "zmm24": unicorn.x86_const.UC_X86_REG_ZMM24,
                "ymm24": unicorn.x86_const.UC_X86_REG_YMM24,
                "xmm24": unicorn.x86_const.UC_X86_REG_XMM24,
                "zmm25": unicorn.x86_const.UC_X86_REG_ZMM25,
                "ymm25": unicorn.x86_const.UC_X86_REG_YMM25,
                "xmm25": unicorn.x86_const.UC_X86_REG_XMM25,
                "zmm26": unicorn.x86_const.UC_X86_REG_ZMM26,
                "ymm26": unicorn.x86_const.UC_X86_REG_YMM26,
                "xmm26": unicorn.x86_const.UC_X86_REG_XMM26,
                "zmm27": unicorn.x86_const.UC_X86_REG_ZMM27,
                "ymm27": unicorn.x86_const.UC_X86_REG_YMM27,
                "xmm27": unicorn.x86_const.UC_X86_REG_XMM27,
                "zmm28": unicorn.x86_const.UC_X86_REG_ZMM28,
                "ymm28": unicorn.x86_const.UC_X86_REG_YMM28,
                "xmm28": unicorn.x86_const.UC_X86_REG_XMM28,
                "zmm29": unicorn.x86_const.UC_X86_REG_ZMM29,
                "ymm29": unicorn.x86_const.UC_X86_REG_YMM29,
                "xmm29": unicorn.x86_const.UC_X86_REG_XMM29,
                "zmm30": unicorn.x86_const.UC_X86_REG_ZMM30,
                "ymm30": unicorn.x86_const.UC_X86_REG_YMM30,
                "xmm30": unicorn.x86_const.UC_X86_REG_XMM30,
                "zmm31": unicorn.x86_const.UC_X86_REG_ZMM31,
                "ymm31": unicorn.x86_const.UC_X86_REG_YMM31,
                "xmm31": unicorn.x86_const.UC_X86_REG_XMM31,
            }
        )
