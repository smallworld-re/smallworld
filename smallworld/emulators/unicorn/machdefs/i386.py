import capstone
import unicorn

from ....platforms import Architecture, Byteorder
from .machdef import UnicornMachineDef


class i386MachineDef(UnicornMachineDef):
    """Unicorn machine definition for i386"""

    arch = Architecture.X86_32
    byteorder = Byteorder.LITTLE

    uc_arch = unicorn.UC_ARCH_X86
    uc_mode = unicorn.UC_MODE_32

    cs_arch = capstone.CS_ARCH_X86
    cs_mode = capstone.CS_MODE_32

    pc_reg = "eip"

    _registers = {
        # *** General Purpose Registers ***
        "eax": (unicorn.x86_const.UC_X86_REG_EAX, "eax", 4, 0),
        "ax": (unicorn.x86_const.UC_X86_REG_AX, "eax", 2, 0),
        "al": (unicorn.x86_const.UC_X86_REG_AL, "eax", 1, 0),
        "ah": (unicorn.x86_const.UC_X86_REG_AH, "eax", 1, 1),
        "ebx": (unicorn.x86_const.UC_X86_REG_EBX, "ebx", 4, 0),
        "bx": (unicorn.x86_const.UC_X86_REG_BX, "ebx", 2, 0),
        "bl": (unicorn.x86_const.UC_X86_REG_BL, "ebx", 1, 0),
        "bh": (unicorn.x86_const.UC_X86_REG_BH, "ebx", 1, 1),
        "ecx": (unicorn.x86_const.UC_X86_REG_ECX, "ecx", 4, 0),
        "cx": (unicorn.x86_const.UC_X86_REG_CX, "ecx", 2, 0),
        "cl": (unicorn.x86_const.UC_X86_REG_CL, "ecx", 1, 0),
        "ch": (unicorn.x86_const.UC_X86_REG_CH, "ecx", 1, 1),
        "edx": (unicorn.x86_const.UC_X86_REG_EDX, "edx", 4, 0),
        "dx": (unicorn.x86_const.UC_X86_REG_DX, "edx", 2, 0),
        "dl": (unicorn.x86_const.UC_X86_REG_DL, "edx", 1, 0),
        "dh": (unicorn.x86_const.UC_X86_REG_DH, "edx", 1, 1),
        "esi": (unicorn.x86_const.UC_X86_REG_ESI, "esi", 4, 0),
        "si": (unicorn.x86_const.UC_X86_REG_SI, "esi", 2, 0),
        "sil": (unicorn.x86_const.UC_X86_REG_SIL, "esi", 1, 0),
        "edi": (unicorn.x86_const.UC_X86_REG_EDI, "edi", 4, 0),
        "di": (unicorn.x86_const.UC_X86_REG_DI, "edi", 2, 0),
        "dil": (unicorn.x86_const.UC_X86_REG_DIL, "edi", 1, 0),
        "ebp": (unicorn.x86_const.UC_X86_REG_EBP, "ebp", 4, 0),
        "bp": (unicorn.x86_const.UC_X86_REG_BP, "ebp", 2, 0),
        "bpl": (unicorn.x86_const.UC_X86_REG_BPL, "ebp", 1, 0),
        "esp": (unicorn.x86_const.UC_X86_REG_ESP, "esp", 4, 0),
        "sp": (unicorn.x86_const.UC_X86_REG_SP, "esp", 2, 0),
        "spl": (unicorn.x86_const.UC_X86_REG_SPL, "esp", 1, 0),
        # *** Instruction Pointer ***
        "eip": (unicorn.x86_const.UC_X86_REG_EIP, "eip", 4, 0),
        "ip": (unicorn.x86_const.UC_X86_REG_IP, "eip", 2, 0),
        # *** Segment Registers ***
        "cs": (unicorn.x86_const.UC_X86_REG_CS, "cs", 2, 0),
        "ss": (unicorn.x86_const.UC_X86_REG_SS, "ss", 2, 0),
        "ds": (unicorn.x86_const.UC_X86_REG_DS, "ds", 2, 0),
        "es": (unicorn.x86_const.UC_X86_REG_ES, "es", 2, 0),
        "fs": (unicorn.x86_const.UC_X86_REG_FS, "fs", 2, 0),
        "gs": (unicorn.x86_const.UC_X86_REG_GS, "gs", 2, 0),
        # *** Flags Registers ***
        "eflags": (unicorn.x86_const.UC_X86_REG_EFLAGS, "eflags", 4, 0),
        "flags": (unicorn.x86_const.UC_X86_REG_FLAGS, "eflags", 2, 0),
        # *** Control Registers ***
        "cr0": (unicorn.x86_const.UC_X86_REG_CR0, "cr0", 4, 0),
        "cr1": (unicorn.x86_const.UC_X86_REG_CR1, "cr1", 4, 0),
        "cr2": (unicorn.x86_const.UC_X86_REG_CR2, "cr2", 4, 0),
        "cr3": (unicorn.x86_const.UC_X86_REG_CR3, "cr3", 4, 0),
        "cr4": (unicorn.x86_const.UC_X86_REG_CR4, "cr4", 4, 0),
        # NOTE: I've got conflicting reports whether cr8 exists in i386.
        "cr8": (unicorn.x86_const.UC_X86_REG_INVALID, "cr8", 4, 0),
        # *** Debug Registers ***
        "dr0": (unicorn.x86_const.UC_X86_REG_DR0, "dr0", 4, 0),
        "dr1": (unicorn.x86_const.UC_X86_REG_DR1, "dr1", 4, 0),
        "dr2": (unicorn.x86_const.UC_X86_REG_DR2, "dr2", 4, 0),
        "dr3": (unicorn.x86_const.UC_X86_REG_DR3, "dr3", 4, 0),
        "dr6": (unicorn.x86_const.UC_X86_REG_DR6, "dr6", 4, 0),
        "dr7": (unicorn.x86_const.UC_X86_REG_DR7, "dr7", 4, 0),
        # *** Descriptor Table Registers
        # NOTE: Yes, this is 6 bytes; 2 byte segment selector plus 4 byte offset
        "gdtr": (unicorn.x86_const.UC_X86_REG_GDTR, "gdtr", 6, 0),
        "idtr": (unicorn.x86_const.UC_X86_REG_IDTR, "idtr", 6, 0),
        "ldtr": (unicorn.x86_const.UC_X86_REG_LDTR, "ldtr", 6, 0),
        # *** Task Register ***
        # NOTE: Yes, this is 6 bytes; 2 byte segment selector plus 4 byte offset
        "tr": (unicorn.x86_const.UC_X86_REG_TR, "tr", 6, 0),
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
        "fstat": (unicorn.x86_const.UC_X86_REG_FPSW, "fstat", 2, 0),
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
        # *** SSE Registers ***
        "xmm0": (unicorn.x86_const.UC_X86_REG_XMM0, "xmm0", 16, 0),
        "xmm1": (unicorn.x86_const.UC_X86_REG_XMM1, "xmm1", 16, 0),
        "xmm2": (unicorn.x86_const.UC_X86_REG_XMM2, "xmm2", 16, 0),
        "xmm3": (unicorn.x86_const.UC_X86_REG_XMM3, "xmm3", 16, 0),
        "xmm4": (unicorn.x86_const.UC_X86_REG_XMM4, "xmm4", 16, 0),
        "xmm5": (unicorn.x86_const.UC_X86_REG_XMM5, "xmm5", 16, 0),
        "xmm6": (unicorn.x86_const.UC_X86_REG_XMM6, "xmm6", 16, 0),
        "xmm7": (unicorn.x86_const.UC_X86_REG_XMM7, "xmm7", 16, 0),
    }
