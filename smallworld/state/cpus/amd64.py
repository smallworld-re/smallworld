from ... import platforms
from .. import state
from . import i386


class AMD64CPUState(i386.i386CPUState):
    """AMD64 CPU state model."""

    _GENERAL_PURPOSE_REGS = [
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rdi",
        "rsi",
        "rbp",
        "rsp",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
    ]

    @classmethod
    def get_platform(cls) -> platforms.Platform:
        return platforms.Platform(
            platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
        )

    def __init__(self):
        self.rax = state.Register("rax", size=8)
        self.eax = state.RegisterAlias("eax", self.rax, size=4)
        self.ax = state.RegisterAlias("ax", self.rax, size=2)
        self.al = state.RegisterAlias("al", self.rax, size=1)
        self.ah = state.RegisterAlias("ah", self.rax, size=1, offset=1)

        self.rbx = state.Register("rbx", size=8)
        self.ebx = state.RegisterAlias("ebx", self.rbx, size=4)
        self.bx = state.RegisterAlias("bx", self.rbx, size=2)
        self.bl = state.RegisterAlias("bl", self.rbx, size=1)
        self.bh = state.RegisterAlias("bh", self.rbx, size=1, offset=1)

        self.rcx = state.Register("rcx", size=8)
        self.ecx = state.RegisterAlias("ecx", self.rcx, size=4)
        self.cx = state.RegisterAlias("cx", self.rcx, size=2)
        self.cl = state.RegisterAlias("cl", self.rcx, size=1)
        self.ch = state.RegisterAlias("ch", self.rcx, size=1, offset=1)

        self.rdx = state.Register("rdx", size=8)
        self.edx = state.RegisterAlias("edx", self.rdx, size=4)
        self.dx = state.RegisterAlias("dx", self.rdx, size=2)
        self.dl = state.RegisterAlias("dl", self.rdx, size=1)
        self.dh = state.RegisterAlias("dh", self.rdx, size=1, offset=1)

        self.r8 = state.Register("r8", size=8)
        self.r8d = state.RegisterAlias("r8d", self.r8, size=4)
        self.r8w = state.RegisterAlias("r8w", self.r8, size=2)
        self.r8b = state.RegisterAlias("r8b", self.r8, size=1)

        self.r9 = state.Register("r9", size=8)
        self.r9d = state.RegisterAlias("r9d", self.r9, size=4)
        self.r9w = state.RegisterAlias("r9w", self.r9, size=2)
        self.r9b = state.RegisterAlias("r9b", self.r9, size=1)

        self.r10 = state.Register("r10", size=8)
        self.r10d = state.RegisterAlias("r10d", self.r10, size=4)
        self.r10w = state.RegisterAlias("r10w", self.r10, size=2)
        self.r10b = state.RegisterAlias("r10b", self.r10, size=1)

        self.r11 = state.Register("r11", size=8)
        self.r11d = state.RegisterAlias("r11d", self.r11, size=4)
        self.r11w = state.RegisterAlias("r11w", self.r11, size=2)
        self.r11b = state.RegisterAlias("r11b", self.r11, size=1)

        self.r12 = state.Register("r12", size=8)
        self.r12d = state.RegisterAlias("r12d", self.r12, size=4)
        self.r12w = state.RegisterAlias("r12w", self.r12, size=2)
        self.r12b = state.RegisterAlias("r12b", self.r12, size=1)

        self.r13 = state.Register("r13", size=8)
        self.r13d = state.RegisterAlias("r13d", self.r13, size=4)
        self.r13w = state.RegisterAlias("r13w", self.r13, size=2)
        self.r13b = state.RegisterAlias("r13b", self.r13, size=1)

        self.r14 = state.Register("r14", size=8)
        self.r14d = state.RegisterAlias("r14d", self.r14, size=4)
        self.r14w = state.RegisterAlias("r14w", self.r14, size=2)
        self.r14b = state.RegisterAlias("r14b", self.r14, size=1)

        self.r15 = state.Register("r15", size=8)
        self.r15d = state.RegisterAlias("r15d", self.r15, size=4)
        self.r15w = state.RegisterAlias("r15w", self.r15, size=2)
        self.r15b = state.RegisterAlias("r15b", self.r15, size=1)

        self.rsi = state.Register("rsi", size=8)
        self.esi = state.RegisterAlias("esi", self.rsi, size=4)
        self.si = state.RegisterAlias("si", self.rsi, size=2)
        self.sil = state.RegisterAlias("sil", self.rsi, size=1)

        self.rdi = state.Register("rdi", size=8)
        self.edi = state.RegisterAlias("edi", self.rdi, size=4)
        self.di = state.RegisterAlias("di", self.rdi, size=2)
        self.dil = state.RegisterAlias("dil", self.rdi, size=1)

        self.rbp = state.Register("rbp", size=8)
        self.ebp = state.RegisterAlias("ebp", self.rbp, size=4)
        self.bp = state.RegisterAlias("bp", self.rbp, size=2)
        self.bpl = state.RegisterAlias("bpl", self.rbp, size=1)

        self.rsp = state.Register("rsp", size=8)
        self.esp = state.RegisterAlias("esp", self.rsp, size=4)
        self.sp = state.RegisterAlias("sp", self.rsp, size=2)
        self.spl = state.RegisterAlias("spl", self.rsp, size=1)

        self.rip = state.Register("rip", size=8)
        self.eip = state.RegisterAlias("eip", self.rip, size=4)
        self.ip = state.RegisterAlias("ip", self.rip, size=2)

        self.cs = state.Register("cs", size=8)
        self.ds = state.Register("ds", size=8)
        self.es = state.Register("es", size=8)
        self.fs = state.Register("fs", size=8)
        self.gs = state.Register("gs", size=8)

        self.rflags = state.Register("rflags", size=8)
        self.eflags = state.RegisterAlias("eflags", self.rflags, size=4)
        self.flags = state.RegisterAlias("flags", self.rflags, size=2)

        self.cr0 = state.Register("cr0", size=8)
        self.cr1 = state.Register("cr1", size=8)
        self.cr2 = state.Register("cr2", size=8)
        self.cr3 = state.Register("cr3", size=8)
        self.cr4 = state.Register("cr4", size=8)
