import unicorn

from ....platforms import Architecture, Byteorder
from .machdef import UnicornMachineDef


class i386MachineDef(UnicornMachineDef):
    """Unicorn machine definition for i386"""

    arch = Architecture.X86_32
    byteorder = Byteorder.LITTLE

    uc_arch = unicorn.UC_ARCH_X86
    uc_mode = unicorn.UC_MODE_32

    _registers = {
        # *** General Purpose Registers ***
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
        # *** Instruction Pointer ***
        "eip": unicorn.x86_const.UC_X86_REG_EIP,
        "ip": unicorn.x86_const.UC_X86_REG_IP,
        # *** Segment Registers ***
        "cs": unicorn.x86_const.UC_X86_REG_CS,
        "ss": unicorn.x86_const.UC_X86_REG_SS,
        "ds": unicorn.x86_const.UC_X86_REG_DS,
        "es": unicorn.x86_const.UC_X86_REG_ES,
        "fs": unicorn.x86_const.UC_X86_REG_FS,
        "gs": unicorn.x86_const.UC_X86_REG_GS,
        # *** Flags Registers ***
        "eflags": unicorn.x86_const.UC_X86_REG_EFLAGS,
        "flags": unicorn.x86_const.UC_X86_REG_FLAGS,
        # *** Control Registers ***
        "cr0": unicorn.x86_const.UC_X86_REG_CR0,
        "cr1": unicorn.x86_const.UC_X86_REG_CR1,
        "cr2": unicorn.x86_const.UC_X86_REG_CR2,
        "cr3": unicorn.x86_const.UC_X86_REG_CR3,
        "cr4": unicorn.x86_const.UC_X86_REG_CR4,
        # NOTE: I've got conflicting reports whether cr8 exists in i386.
        "cr8": unicorn.x86_const.UC_X86_REG_INVALID,
        # *** Debug Registers ***
        "dr0": unicorn.x86_const.UC_X86_REG_DR0,
        "dr1": unicorn.x86_const.UC_X86_REG_DR1,
        "dr2": unicorn.x86_const.UC_X86_REG_DR2,
        "dr3": unicorn.x86_const.UC_X86_REG_DR3,
        "dr6": unicorn.x86_const.UC_X86_REG_DR6,
        "dr7": unicorn.x86_const.UC_X86_REG_DR7,
        # *** Descriptor Table Registers
        # NOTE: Yes, this is 6 bytes; 2 byte segment selector plus 4 byte offset
        "gdtr": unicorn.x86_const.UC_X86_REG_GDTR,
        "idtr": unicorn.x86_const.UC_X86_REG_IDTR,
        "ldtr": unicorn.x86_const.UC_X86_REG_LDTR,
        # *** Task Register ***
        # NOTE: Yes, this is 6 bytes; 2 byte segment selector plus 4 byte offset
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
        "fstat": unicorn.x86_const.UC_X86_REG_FPSW,
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
        # *** SSE Registers ***
        "xmm0": unicorn.x86_const.UC_X86_REG_XMM0,
        "xmm1": unicorn.x86_const.UC_X86_REG_XMM1,
        "xmm2": unicorn.x86_const.UC_X86_REG_XMM2,
        "xmm3": unicorn.x86_const.UC_X86_REG_XMM3,
        "xmm4": unicorn.x86_const.UC_X86_REG_XMM4,
        "xmm5": unicorn.x86_const.UC_X86_REG_XMM5,
        "xmm6": unicorn.x86_const.UC_X86_REG_XMM6,
        "xmm7": unicorn.x86_const.UC_X86_REG_XMM7,
    }
