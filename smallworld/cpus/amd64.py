from .. import state
from . import i386


class AMD64CPUState(i386.i386CPUState):
    """AMD64 CPU state model.

    See arguments for i386CPUState.
    """

    BITS = 64
    STACK_POINTER = "rsp"

    def __init__(self, *args, **kwargs):
        self.rax = state.Register("rax", width=8)
        self.eax = state.RegisterAlias("eax", self.rax, width=4)
        self.ax = state.RegisterAlias("ax", self.rax, width=2)
        self.al = state.RegisterAlias("al", self.rax, width=1)
        self.ah = state.RegisterAlias("ah", self.rax, width=1, offset=1)

        self.rbx = state.Register("rbx", width=8)
        self.ebx = state.RegisterAlias("ebx", self.rbx, width=4)
        self.bx = state.RegisterAlias("bx", self.rbx, width=2)
        self.bl = state.RegisterAlias("bl", self.rbx, width=1)
        self.bh = state.RegisterAlias("bh", self.rbx, width=1, offset=1)

        self.rcx = state.Register("rcx", width=8)
        self.ecx = state.RegisterAlias("ecx", self.rcx, width=4)
        self.cx = state.RegisterAlias("cx", self.rcx, width=2)
        self.cl = state.RegisterAlias("cl", self.rcx, width=1)
        self.ch = state.RegisterAlias("ch", self.rcx, width=1, offset=1)

        self.rdx = state.Register("rdx", width=8)
        self.edx = state.RegisterAlias("edx", self.rdx, width=4)
        self.dx = state.RegisterAlias("dx", self.rdx, width=2)
        self.dl = state.RegisterAlias("dl", self.rdx, width=1)
        self.dh = state.RegisterAlias("dh", self.rdx, width=1, offset=1)

        self.r8 = state.Register("r8", width=8)
        self.r8d = state.RegisterAlias("r8d", self.r8, width=4)
        self.r8w = state.RegisterAlias("r8w", self.r8, width=2)
        self.r8b = state.RegisterAlias("r8b", self.r8, width=1)

        self.r9 = state.Register("r9", width=8)
        self.r9d = state.RegisterAlias("r9d", self.r9, width=4)
        self.r9w = state.RegisterAlias("r9w", self.r9, width=2)
        self.r9b = state.RegisterAlias("r9b", self.r9, width=1)

        self.r10 = state.Register("r10", width=8)
        self.r10d = state.RegisterAlias("r10d", self.r10, width=4)
        self.r10w = state.RegisterAlias("r10w", self.r10, width=2)
        self.r10b = state.RegisterAlias("r10b", self.r10, width=1)

        self.r11 = state.Register("r11", width=8)
        self.r11d = state.RegisterAlias("r11d", self.r11, width=4)
        self.r11w = state.RegisterAlias("r11w", self.r11, width=2)
        self.r11b = state.RegisterAlias("r11b", self.r11, width=1)

        self.r12 = state.Register("r12", width=8)
        self.r12d = state.RegisterAlias("r12d", self.r12, width=4)
        self.r12w = state.RegisterAlias("r12w", self.r12, width=2)
        self.r12b = state.RegisterAlias("r12b", self.r12, width=1)

        self.r13 = state.Register("r13", width=8)
        self.r13d = state.RegisterAlias("r13d", self.r13, width=4)
        self.r13w = state.RegisterAlias("r13w", self.r13, width=2)
        self.r13b = state.RegisterAlias("r13b", self.r13, width=1)

        self.r14 = state.Register("r14", width=8)
        self.r14d = state.RegisterAlias("r14d", self.r14, width=4)
        self.r14w = state.RegisterAlias("r14w", self.r14, width=2)
        self.r14b = state.RegisterAlias("r14b", self.r14, width=1)

        self.r15 = state.Register("r15", width=8)
        self.r15d = state.RegisterAlias("r15d", self.r15, width=4)
        self.r15w = state.RegisterAlias("r15w", self.r15, width=2)
        self.r15b = state.RegisterAlias("r15b", self.r15, width=1)

        self.rsi = state.Register("rsi", width=8)
        self.esi = state.RegisterAlias("esi", self.rsi, width=4)
        self.si = state.RegisterAlias("si", self.rsi, width=2)
        self.sil = state.RegisterAlias("sil", self.rsi, width=1)

        self.rdi = state.Register("rdi", width=8)
        self.edi = state.RegisterAlias("edi", self.rdi, width=4)
        self.di = state.RegisterAlias("di", self.rdi, width=2)
        self.dil = state.RegisterAlias("dil", self.rdi, width=1)

        self.rbp = state.Register("rbp", width=8)
        self.ebp = state.RegisterAlias("ebp", self.rbp, width=4)
        self.bp = state.RegisterAlias("bp", self.rbp, width=2)
        self.bpl = state.RegisterAlias("bpl", self.rbp, width=1)

        self.rsp = state.Register("rsp", width=8)
        self.esp = state.RegisterAlias("esp", self.rsp, width=4)
        self.sp = state.RegisterAlias("sp", self.rsp, width=2)
        self.spl = state.RegisterAlias("spl", self.rsp, width=1)

        self.rip = state.Register("rip", width=8)
        self.eip = state.RegisterAlias("eip", self.rip, width=4)
        self.ip = state.RegisterAlias("ip", self.rip, width=2)

        self.cs = state.Register("cs", width=8)
        self.ds = state.Register("ds", width=8)
        self.es = state.Register("es", width=8)
        self.fs = state.Register("fs", width=8)
        self.gs = state.Register("gs", width=8)

        self.rflags = state.Register("rflags", width=8)
        self.eflags = state.RegisterAlias("eflags", self.rflags, width=4)
        self.flags = state.RegisterAlias("flags", self.rflags, width=2)

        self.cr0 = state.Register("cr0", width=8)
        self.cr1 = state.Register("cr1", width=8)
        self.cr2 = state.Register("cr2", width=8)
        self.cr3 = state.Register("cr3", width=8)
        self.cr4 = state.Register("cr4", width=8)

        self.setup(*args, **kwargs)
