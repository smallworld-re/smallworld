from ....platforms import Architecture, Byteorder
from .machdef import PcodeMachineDef


class i386MachineDef(PcodeMachineDef):
    arch = Architecture.X86_32
    byteorder = Byteorder.LITTLE
    language_id = "x86:LE:32:default"

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
        "cr0": "cr0",
        "cr1": None,
        "cr2": "cr2",
        "cr3": "cr3",
        "cr4": "cr4",
        "cr8": None,
        # *** Debug Registers ***
        "dr0": "dr0",
        "dr1": "dr1",
        "dr2": "dr2",
        "dr3": "dr3",
        "dr6": "dr6",
        "dr7": "dr7",
        # *** Descriptor Table Registers ***
        "gdtr": "gdtr",
        "idtr": "idtr",
        "ldtr": "ldtr",
        # *** Task Register ***
        "tr": "tr",
        # *** x87 Registers ***
        # TODO: Ghidra seems to support x87, but I have no idea how its register file works
        # I can't find most of the control registers,
        # and there don't seem to be separate "fprN" registers; the stack references.
        "fpr0": None,
        "fpr1": None,
        "fpr2": None,
        "fpr3": None,
        "fpr4": None,
        "fpr5": None,
        "fpr6": None,
        "fpr7": None,
        "fctrl": None,
        "fstat": None,
        "ftag": None,
        "fip": None,
        "fdp": None,
        "fop": None,
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
