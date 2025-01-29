import archinfo

from ....platforms import Architecture, Byteorder
from .machdef import AngrMachineDef


class i386MachineDef(AngrMachineDef):
    arch = Architecture.X86_32
    byteorder = Byteorder.LITTLE

    angr_arch = archinfo.arch_x86.ArchX86()

    pc_reg = "eip"

    _registers = {
        # *** General Purpose Registers ***
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
        # *** Instruction Pointer ***
        "eip": "eip",
        "ip": "ip",
        # *** Segment Registers ***
        "cs": "cs",
        "ds": "ds",
        "es": "es",
        "fs": "fs",
        "gs": "gs",
        "ss": "ss",
        # *** Flags Register ***
        "eflags": "eflags",
        "flags": "flags",
        # *** Control Registers ***
        "cr0": "",
        "cr1": "",
        "cr2": "",
        "cr3": "",
        "cr4": "",
        "cr8": "",
        # *** Debug Registers ***
        "dr0": "",
        "dr1": "",
        "dr2": "",
        "dr3": "",
        "dr6": "",
        "dr7": "",
        # *** Descriptor Table Registers ***
        "gdtr": "gdt",
        "idtr": "idt",
        "ldtr": "ldt",
        # *** Task Register ***
        "tr": "",
        # *** x87 Registers ***
        # TODO: angr seems to support x87, but I have no idea how its register file works
        # I can't find most of the control registers,
        # and there don't seem to be separate "fprN" registers; just one giant blob
        "fpr0": "",
        "fpr1": "",
        "fpr2": "",
        "fpr3": "",
        "fpr4": "",
        "fpr5": "",
        "fpr6": "",
        "fpr7": "",
        "fctrl": "",
        "fstat": "",
        "ftag": "fptag",
        "fip": "",
        "fdp": "",
        "fop": "",
        # *** MMX Registers ***
        "mm0": "mm0",
        "mm1": "mm1",
        "mm2": "mm2",
        "mm3": "mm3",
        "mm4": "mm4",
        "mm5": "mm5",
        "mm6": "mm6",
        "mm7": "mm7",
        # *** SSE Registers ***
        "xmm0": "xmm0",
        "xmm1": "xmm1",
        "xmm2": "xmm2",
        "xmm3": "xmm3",
        "xmm4": "xmm4",
        "xmm5": "xmm5",
        "xmm6": "xmm6",
        "xmm7": "xmm7",
    }
