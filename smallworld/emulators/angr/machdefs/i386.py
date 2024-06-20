import archinfo

from .machdef import AngrMachineDef


class i386MachineDef(AngrMachineDef):
    arch = "x86"
    mode = "32"
    byteorder = "little"

    angr_arch = archinfo.arch_x86.ArchX86()

    pc_reg = "eip"

    _registers = {
        # Yes, this is the identity mapping.
        # I'm not sorry.
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
        "eip": "eip",
        "ip": "ip",
        "cs": "cs",
        "ds": "ds",
        "es": "es",
        "fs": "fs",
        "gs": "gs",
        "eflags": "eflags",
        "flags": "flags",
        "cr0": "cr0",
        "cr1": "cr1",
        "cr2": "cr2",
        "cr3": "cr3",
        "cr4": "cr4",
    }
