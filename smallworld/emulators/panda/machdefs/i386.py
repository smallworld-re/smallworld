from ....platforms import Architecture, Byteorder
from .machdef import PandaMachineDef


class i386MachineDef(PandaMachineDef):
    arch = Architecture.X86_32
    byteorder = Byteorder.LITTLE

    panda_arch = "i386"

    # I'm going to define all the ones we are making possible as of now
    # I need to submit a PR to change to X86 32 bit and to includ eflags
    _registers_general = {"eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "eip"}
    _registers_short = {"ax", "bx", "cx", "dx", "si", "di", "sp", "bp"}
    _registers_byte = {"al", "bl", "cl", "dl", "ah", "bh", "ch", "dh"}
    _registers_flags = {"eflags", "flags"}
    _registers_seg = {"es", "cs", "ss", "ds", "fs", "gs"}
    _registers_control = {"cr0", "cr1", "cr2", "cr3", "cr4"}
    _registers_debug = {"dr0", "dr1", "dr2", "dr3", "dr6", "dr7"}
    _registers_mmr = {"gdtr": "gdt", "idtr": "idt", "tr": "tr", "ldtr": "ldt"}
    _registers_x87 = {
        "fpr0",
        "fpr1",
        "fpr2",
        "fpr3",
        "fpr4",
        "fpr5",
        "fpr6",
        "fpr7",
        "fctrl",
        "fstat",
        "ftag",
        "fip",
        "fdp",
        "fop",
    }
    _registers_mmx = {"mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7"}
    _registers_xmm = {"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"}
    _registers_pc = {"pc": "eip", "ip": None}
    _registers_absent = {"dil", "sil", "spl", "bpl", "cr8"}

    _registers = {}
    _registers = _registers | {i: i for i in _registers_general}
    _registers = _registers | {i: i for i in _registers_short}
    _registers = _registers | {i: i for i in _registers_byte}
    _registers = _registers | {i: None for i in _registers_flags}
    _registers = _registers | {i: i for i in _registers_seg}
    _registers = _registers | {i: i for i in _registers_control}
    _registers = _registers | {i: None for i in _registers_debug}
    _registers = _registers | {i: j for i, j in _registers_mmr.items()}
    _registers = _registers | {i: None for i in _registers_x87}
    _registers = _registers | {i: None for i in _registers_mmx}
    _registers = _registers | {i: None for i in _registers_xmm}
    _registers = _registers | {i: j for i, j in _registers_pc.items()}
    _registers = _registers | {i: None for i in _registers_absent}
    # _registers = (
    #    _registers_general | _registers_byte | _registers_seg | _registers_control
    # )
    # _registers = {**_registers_general, **_register_short, **_registers_seg, **_registers_control}
