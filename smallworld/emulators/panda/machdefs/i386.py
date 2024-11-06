import capstone

from ....platforms import Architecture, Byteorder
from .machdef import PandaMachineDef


class i386MachineDef(PandaMachineDef):
    arch = Architecture.X86_32
    byteorder = Byteorder.LITTLE

    panda_arch = "i386"

    cs_arch = capstone.CS_ARCH_X86
    cs_mode = capstone.CS_MODE_32

    # I'm going to define all the ones we are making possible as of now
    # I need to submit a PR to change to X86 32 bit and to includ eflags
    _registers_general = {"eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "eip"}
    _registers_short = {"ax", "bx", "cx", "dx", "si", "di", "sp", "bp"}
    _registers_byte = {"al", "bl", "cl", "dl", "ah", "bh", "ch", "dh"}
    _registers_seg = {"es", "cs", "ss", "ds", "fs", "gs"}
    _registers_control = {"cr0", "cr1", "cr2", "cr3", "cr4"}
    _registers_mmr = {"gdtr": "gdt", "idtr": "idt", "tr": "tr", "ldtr": "ldt"}
    _register_pc = {"pc": "eip"}

    _registers = {}
    _registers = _registers | {i: i for i in _registers_general}
    _registers = _registers | {i: i for i in _registers_byte}
    _registers = _registers | {i: i for i in _registers_seg}
    _registers = _registers | {i: i for i in _registers_control}
    _registers = _registers | {i: j for i, j in _registers_mmr.items()}
    _registers = _registers | {i: j for i, j in _register_pc.items()}
    # _registers = (
    #    _registers_general | _registers_byte | _registers_seg | _registers_control
    # )
    # _registers = {**_registers_general, **_register_short, **_registers_seg, **_registers_control}
