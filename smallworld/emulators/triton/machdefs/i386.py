from triton import ARCH

from ....platforms import Architecture, Byteorder
from .machdef import TritonMachineDef

# SmallWorld canonical register name -> Triton register name (x86-32). As with
# amd64, the flags register collapses onto ``eflags`` (32-bit wide here) and the
# x87 register family is renamed. ``gdtr``/``idtr``/``ldtr``/``tr`` have no
# Triton equivalent and are omitted (-> UnsupportedRegisterError).
_I386_REGISTERS = {
    "eax": "eax",
    "ax": "ax",
    "al": "al",
    "ah": "ah",
    "ebx": "ebx",
    "bx": "bx",
    "bl": "bl",
    "bh": "bh",
    "ecx": "ecx",
    "cx": "cx",
    "cl": "cl",
    "ch": "ch",
    "edx": "edx",
    "dx": "dx",
    "dl": "dl",
    "dh": "dh",
    "esi": "esi",
    "si": "si",
    "sil": "sil",
    "edi": "edi",
    "di": "di",
    "dil": "dil",
    "ebp": "ebp",
    "bp": "bp",
    "bpl": "bpl",
    "esp": "esp",
    "sp": "sp",
    "spl": "spl",
    # Instruction pointer (``pc`` handled by pc_register translation).
    "eip": "eip",
    "ip": "ip",
    # Segment registers.
    "cs": "cs",
    "ss": "ss",
    "ds": "ds",
    "es": "es",
    "fs": "fs",
    "gs": "gs",
    # Flags (32-bit ``eflags``).
    "eflags": "eflags",
    "flags": "eflags",
    # Control registers.
    "cr0": "cr0",
    "cr1": "cr1",
    "cr2": "cr2",
    "cr3": "cr3",
    "cr4": "cr4",
    "cr8": "cr8",
    # Debug registers.
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
    # SSE.
    "xmm0": "xmm0",
    "xmm1": "xmm1",
    "xmm2": "xmm2",
    "xmm3": "xmm3",
    "xmm4": "xmm4",
    "xmm5": "xmm5",
    "xmm6": "xmm6",
    "xmm7": "xmm7",
}


class TritonI386MachineDef(TritonMachineDef):
    """Triton machine definition for x86-32."""

    arch = Architecture.X86_32
    byteorder = Byteorder.LITTLE
    triton_arch = ARCH.X86
    pc_register = "eip"
    sp_register = "esp"
    lr_register = None
    address_size = 4
    interrupt_mnemonics = {"int", "int3", "sysenter"}
    _registers = _I386_REGISTERS
