import capstone

from ....platforms import Architecture, Byteorder
from .machdef import PandaMachineDef


class AMD64MachineDef(PandaMachineDef):
    arch = Architecture.X86_64
    byteorder = Byteorder.LITTLE

    panda_arch = "x86_64"

    cs_arch = capstone.CS_ARCH_X86
    cs_mode = capstone.CS_MODE_64

    # I'm going to define all the ones we are making possible as of now
    # I need to submit a PR to change to X86 32 bit and to includ eflags
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
    _registers_general = {"eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "eip"}
    _registers_short = {"ax", "bx", "cx", "dx", "si", "di", "sp", "bp"}
    _registers_byte = {"al", "bl", "cl", "dl", "ah", "bh", "ch", "dh"}
    _registers_seg = {"es", "cs", "ss", "ds", "fs", "gs"}
    _registers_control = {"cr0", "cr1", "cr2", "cr3", "cr4"}
    _registers_mmr = {"gdtr": "gdt", "idtr": "idt", "tr": "tr", "ldtr": "ldt"}
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
    _register_pc = {"pc": "rip"}

    _registers = {}
    _registers = _registers | {i: i for i in _registers_64}
    _registers = _registers | {i: i for i in _registers_general}
    _registers = _registers | {i: i for i in _registers_byte}
    _registers = _registers | {i: i for i in _registers_seg}
    _registers = _registers | {i: i for i in _registers_control}
    _registers = _registers | {i: j for i, j in _registers_mmr.items()}
    _registers = _registers | {i: i for i in _registers_xmm}
    _registers = _registers | {i: j for i, j in _register_pc.items()}
