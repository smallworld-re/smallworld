from ....platforms import Architecture, Byteorder
from .machdef import PandaMachineDef


class AMD64MachineDef(PandaMachineDef):
    arch = Architecture.X86_64
    byteorder = Byteorder.LITTLE

    panda_arch = "x86_64"

    # I'm going to define all the ones we are making possible as of now
    # I need to submit a PR to change to X86 32 bit and to include eflags
    _registers_64 = {
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "rsp",
        "rbp",
        "rip",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
    }
    _registers_general = {
        "eax",
        "ebx",
        "ecx",
        "edx",
        "esi",
        "edi",
        "esp",
        "ebp",
        "eip",
        "r8d",
        "r9d",
        "r10d",
        "r11d",
        "r12d",
        "r13d",
        "r14d",
        "r15d",
    }
    _registers_short = {
        "ax",
        "bx",
        "cx",
        "dx",
        "si",
        "di",
        "sp",
        "bp",
        "r8w",
        "r9w",
        "r10w",
        "r11w",
        "r12w",
        "r13w",
        "r14w",
        "r15w",
    }
    _registers_byte = {
        "al",
        "bl",
        "cl",
        "dl",
        "r8b",
        "r9b",
        "r10b",
        "r11b",
        "r12b",
        "r13b",
        "r14b",
        "r15b",
        "ah",
        "bh",
        "ch",
        "dh",
    }
    _registers_flags = {"rflags", "eflags", "flags"}
    _registers_seg = {"es", "cs", "ss", "ds", "fs", "gs"}
    _registers_control = {"cr0", "cr1", "cr2", "cr3", "cr4"}
    _registers_debug = {f"dr{i}" for i in range(0, 16)} - {"dr4", "dr5"}
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
    _registers_xmm = {
        "xmm0",
        "xmm1",
        "xmm2",
        "xmm3",
        "xmm4",
        "xmm5",
        "xmm6",
        "xmm7",
        "xmm8",
        "xmm9",
        "xmm10",
        "xmm11",
        "xmm12",
        "xmm13",
        "xmm14",
        "xmm15",
    }
    _registers_ymm = {
        "ymm0",
        "ymm1",
        "ymm2",
        "ymm3",
        "ymm4",
        "ymm5",
        "ymm6",
        "ymm7",
        "ymm8",
        "ymm9",
        "ymm10",
        "ymm11",
        "ymm12",
        "ymm13",
        "ymm14",
        "ymm15",
    }
    _registers_msr = {"fsbase", "gsbase"}
    _registers_pc = {"pc": "rip", "eip": "eip", "ip": None}
    _registers_absent = {"dil", "sil", "spl", "bpl", "cr8"}

    _registers = {}
    _registers = _registers | {i: i for i in _registers_64}
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
    _registers = _registers | {i: i for i in _registers_xmm}
    _registers = _registers | {i: None for i in _registers_ymm}
    _registers = _registers | {i: j for i, j in _registers_pc.items()}
    _registers = _registers | {i: None for i in _registers_absent}
    _registers = _registers | {i: None for i in _registers_msr}
