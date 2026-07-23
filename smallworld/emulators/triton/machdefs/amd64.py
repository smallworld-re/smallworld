from triton import ARCH

from ....platforms import Architecture, Byteorder
from .machdef import TritonMachineDef

# SmallWorld canonical register name -> Triton register name (x86-64).
# Almost every mapping is an identity; the exceptions are the flags register
# (Triton exposes only ``eflags``, whose width Triton fixes per architecture)
# and the x87 register family (``fpr*``->``st*``, ``fctrl``->``fcw`` etc.).
# Registers Triton has no equivalent for (``gdtr``/``idtr``/``ldtr``/``tr``,
# ``fsbase``/``gsbase``, ``dr8``+) are intentionally omitted so that reading
# them raises ``UnsupportedRegisterError``.
_AMD64_REGISTERS = {
    "rax": "rax",
    "eax": "eax",
    "ax": "ax",
    "al": "al",
    "ah": "ah",
    "rbx": "rbx",
    "ebx": "ebx",
    "bx": "bx",
    "bl": "bl",
    "bh": "bh",
    "rcx": "rcx",
    "ecx": "ecx",
    "cx": "cx",
    "cl": "cl",
    "ch": "ch",
    "rdx": "rdx",
    "edx": "edx",
    "dx": "dx",
    "dl": "dl",
    "dh": "dh",
    "r8": "r8",
    "r8d": "r8d",
    "r8w": "r8w",
    "r8b": "r8b",
    "r9": "r9",
    "r9d": "r9d",
    "r9w": "r9w",
    "r9b": "r9b",
    "r10": "r10",
    "r10d": "r10d",
    "r10w": "r10w",
    "r10b": "r10b",
    "r11": "r11",
    "r11d": "r11d",
    "r11w": "r11w",
    "r11b": "r11b",
    "r12": "r12",
    "r12d": "r12d",
    "r12w": "r12w",
    "r12b": "r12b",
    "r13": "r13",
    "r13d": "r13d",
    "r13w": "r13w",
    "r13b": "r13b",
    "r14": "r14",
    "r14d": "r14d",
    "r14w": "r14w",
    "r14b": "r14b",
    "r15": "r15",
    "r15d": "r15d",
    "r15w": "r15w",
    "r15b": "r15b",
    "rdi": "rdi",
    "edi": "edi",
    "di": "di",
    "dil": "dil",
    "rsi": "rsi",
    "esi": "esi",
    "si": "si",
    "sil": "sil",
    "rsp": "rsp",
    "esp": "esp",
    "sp": "sp",
    "spl": "spl",
    "rbp": "rbp",
    "ebp": "ebp",
    "bp": "bp",
    "bpl": "bpl",
    # Instruction pointer (``pc`` is handled by pc_register translation).
    "rip": "rip",
    "eip": "eip",
    "ip": "ip",
    # Flags: Triton has only ``eflags`` (64-bit wide in x86-64 mode).
    "rflags": "eflags",
    "eflags": "eflags",
    "flags": "eflags",
    # Segment registers.
    "cs": "cs",
    "ds": "ds",
    "es": "es",
    "fs": "fs",
    "gs": "gs",
    "ss": "ss",
    # Control registers.
    "cr0": "cr0",
    "cr1": "cr1",
    "cr2": "cr2",
    "cr3": "cr3",
    "cr4": "cr4",
    "cr8": "cr8",
    # Debug registers (Triton has only dr0-3, dr6, dr7).
    "dr0": "dr0",
    "dr1": "dr1",
    "dr2": "dr2",
    "dr3": "dr3",
    "dr6": "dr6",
    "dr7": "dr7",
    # x87 register file.
    "fpr0": "st0",
    "fpr1": "st1",
    "fpr2": "st2",
    "fpr3": "st3",
    "fpr4": "st4",
    "fpr5": "st5",
    "fpr6": "st6",
    "fpr7": "st7",
    "fctrl": "fcw",
    "fstat": "fsw",
    "ftag": "ftw",
    "fip": "fip",
    "fdp": "fdp",
    "fop": "fop",
    # MMX.
    "mm0": "mm0",
    "mm1": "mm1",
    "mm2": "mm2",
    "mm3": "mm3",
    "mm4": "mm4",
    "mm5": "mm5",
    "mm6": "mm6",
    "mm7": "mm7",
    # SSE/AVX.
    "xmm0": "xmm0",
    "xmm1": "xmm1",
    "xmm2": "xmm2",
    "xmm3": "xmm3",
    "xmm4": "xmm4",
    "xmm5": "xmm5",
    "xmm6": "xmm6",
    "xmm7": "xmm7",
    "xmm8": "xmm8",
    "xmm9": "xmm9",
    "xmm10": "xmm10",
    "xmm11": "xmm11",
    "xmm12": "xmm12",
    "xmm13": "xmm13",
    "xmm14": "xmm14",
    "xmm15": "xmm15",
    "ymm0": "ymm0",
    "ymm1": "ymm1",
    "ymm2": "ymm2",
    "ymm3": "ymm3",
    "ymm4": "ymm4",
    "ymm5": "ymm5",
    "ymm6": "ymm6",
    "ymm7": "ymm7",
    "ymm8": "ymm8",
    "ymm9": "ymm9",
    "ymm10": "ymm10",
    "ymm11": "ymm11",
    "ymm12": "ymm12",
    "ymm13": "ymm13",
    "ymm14": "ymm14",
    "ymm15": "ymm15",
}


class TritonAMD64MachineDef(TritonMachineDef):
    """Triton machine definition for x86-64."""

    arch = Architecture.X86_64
    byteorder = Byteorder.LITTLE
    triton_arch = ARCH.X86_64
    pc_register = "rip"
    sp_register = "rsp"
    lr_register = None
    address_size = 8
    interrupt_mnemonics = {"int", "int3", "syscall", "sysenter"}
    _registers = _AMD64_REGISTERS


class TritonAMD64AVX512MachineDef(TritonAMD64MachineDef):
    """Triton machine definition for x86-64 with AVX-512.

    Triton has no distinct AVX-512 architecture, so this reuses ``ARCH.X86_64``
    and the base register map; the ``zmm*`` registers SmallWorld's AVX-512
    platform adds are unsupported by Triton and therefore raise
    ``UnsupportedRegisterError``.
    """

    arch = Architecture.X86_64_AVX512
