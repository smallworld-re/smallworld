import capstone
import pandare

from ....platforms import Architecture, Byteorder
from .machdef import PandaMachineDef


class AMD64MachineDef(PandaMachineDef):
    arch = Architecture.X86_64
    byteorder = Byteorder.LITTLE

    panda_arch_str = "x86_64"
    panda_cpu_str = ""
    panda_arch = pandare.arch.X86_64Arch(None)

    cs_arch = capstone.CS_ARCH_X86
    cs_mode = capstone.CS_MODE_64

    pc_reg = "rip"

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

    # _registers = (
    #    _registers_64
    #    | _registers_general
    #    | _registers_byte
    #    | _registers_seg
    #    | _registers_control
    # )
    _registers = {}
    _registers = _registers | {i: i for i in _registers_64}
    _registers = _registers | {i: i for i in _registers_general}
    _registers = _registers | {i: i for i in _registers_byte}
    _registers = _registers | {i: i for i in _registers_seg}
    _registers = _registers | {i: i for i in _registers_control}
