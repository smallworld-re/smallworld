import typing

from ... import platforms
from .. import state
from ..x86_registers import X86MMRRegister
from . import cpu


class AMD64(cpu.CPU):
    """Generic AMD64 CPU state model.

    Specific implementations support different vector extensions.
    Because of how smallworld works, an emulator can only support
    platforms if it supports all base registers.
    Since the AVX extensions keep adding registers under
    the old ones, we need new platforms.
    """

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

    def get_general_purpose_registers(self) -> typing.List[str]:
        return self._GENERAL_PURPOSE_REGS

    def __init__(self):
        super().__init__()
        # *** General Purpose Registers ***
        self.rax = state.Register("rax", 8)
        self.add(self.rax)
        self.eax = state.RegisterAlias("eax", self.rax, 4, 0)
        self.add(self.eax)
        self.ax = state.RegisterAlias("ax", self.rax, 2, 0)
        self.add(self.ax)
        self.al = state.RegisterAlias("al", self.rax, 1, 0)
        self.add(self.al)
        self.ah = state.RegisterAlias("ah", self.rax, 1, 1)
        self.add(self.ah)

        self.rbx = state.Register("rbx", 8)
        self.add(self.rbx)
        self.ebx = state.RegisterAlias("ebx", self.rbx, 4, 0)
        self.add(self.ebx)
        self.bx = state.RegisterAlias("bx", self.rbx, 2, 0)
        self.add(self.bx)
        self.bl = state.RegisterAlias("bl", self.rbx, 1, 0)
        self.add(self.bl)
        self.bh = state.RegisterAlias("bh", self.rbx, 1, 1)
        self.add(self.bh)

        self.rcx = state.Register("rcx", 8)
        self.add(self.rcx)
        self.ecx = state.RegisterAlias("ecx", self.rcx, 4, 0)
        self.add(self.ecx)
        self.cx = state.RegisterAlias("cx", self.rcx, 2, 0)
        self.add(self.cx)
        self.cl = state.RegisterAlias("cl", self.rcx, 1, 0)
        self.add(self.cl)
        self.ch = state.RegisterAlias("ch", self.rcx, 1, 1)
        self.add(self.ch)

        self.rdx = state.Register("rdx", 8)
        self.add(self.rdx)
        self.edx = state.RegisterAlias("edx", self.rdx, 4, 0)
        self.add(self.edx)
        self.dx = state.RegisterAlias("dx", self.rdx, 2, 0)
        self.add(self.dx)
        self.dl = state.RegisterAlias("dl", self.rdx, 1, 0)
        self.add(self.dl)
        self.dh = state.RegisterAlias("dh", self.rdx, 1, 1)
        self.add(self.dh)

        self.r8 = state.Register("r8", 8)
        self.add(self.r8)
        self.r8d = state.RegisterAlias("r8d", self.r8, 4, 0)
        self.add(self.r8d)
        self.r8w = state.RegisterAlias("r8w", self.r8, 2, 0)
        self.add(self.r8w)
        self.r8b = state.RegisterAlias("r8b", self.r8, 1, 0)
        self.add(self.r8b)

        self.r9 = state.Register("r9", 8)
        self.add(self.r9)
        self.r9d = state.RegisterAlias("r9d", self.r9, 4, 0)
        self.add(self.r9d)
        self.r9w = state.RegisterAlias("r9w", self.r9, 2, 0)
        self.add(self.r9w)
        self.r9b = state.RegisterAlias("r9b", self.r9, 1, 0)
        self.add(self.r9b)

        self.r10 = state.Register("r10", 8)
        self.add(self.r10)
        self.r10d = state.RegisterAlias("r10d", self.r10, 4, 0)
        self.add(self.r10d)
        self.r10w = state.RegisterAlias("r10w", self.r10, 2, 0)
        self.add(self.r10w)
        self.r10b = state.RegisterAlias("r10b", self.r10, 1, 0)
        self.add(self.r10b)

        self.r11 = state.Register("r11", 8)
        self.add(self.r11)
        self.r11d = state.RegisterAlias("r11d", self.r11, 4, 0)
        self.add(self.r11d)
        self.r11w = state.RegisterAlias("r11w", self.r11, 2, 0)
        self.add(self.r11w)
        self.r11b = state.RegisterAlias("r11b", self.r11, 1, 0)
        self.add(self.r11b)

        self.r12 = state.Register("r12", 8)
        self.add(self.r12)
        self.r12d = state.RegisterAlias("r12d", self.r12, 4, 0)
        self.add(self.r12d)
        self.r12w = state.RegisterAlias("r12w", self.r12, 2, 0)
        self.add(self.r12w)
        self.r12b = state.RegisterAlias("r12b", self.r12, 1, 0)
        self.add(self.r12b)

        self.r13 = state.Register("r13", 8)
        self.add(self.r13)
        self.r13d = state.RegisterAlias("r13d", self.r13, 4, 0)
        self.add(self.r13d)
        self.r13w = state.RegisterAlias("r13w", self.r13, 2, 0)
        self.add(self.r13w)
        self.r13b = state.RegisterAlias("r13b", self.r13, 1, 0)
        self.add(self.r13b)

        self.r14 = state.Register("r14", 8)
        self.add(self.r14)
        self.r14d = state.RegisterAlias("r14d", self.r14, 4, 0)
        self.add(self.r14d)
        self.r14w = state.RegisterAlias("r14w", self.r14, 2, 0)
        self.add(self.r14w)
        self.r14b = state.RegisterAlias("r14b", self.r14, 1, 0)
        self.add(self.r14b)

        self.r15 = state.Register("r15", 8)
        self.add(self.r15)
        self.r15d = state.RegisterAlias("r15d", self.r15, 4, 0)
        self.add(self.r15d)
        self.r15w = state.RegisterAlias("r15w", self.r15, 2, 0)
        self.add(self.r15w)
        self.r15b = state.RegisterAlias("r15b", self.r15, 1, 0)
        self.add(self.r15b)

        self.rdi = state.Register("rdi", 8)
        self.add(self.rdi)
        self.edi = state.RegisterAlias("edi", self.rdi, 4, 0)
        self.add(self.edi)
        self.di = state.RegisterAlias("di", self.rdi, 2, 0)
        self.add(self.di)
        self.dil = state.RegisterAlias("dil", self.rdi, 1, 0)
        self.add(self.dil)

        self.rsi = state.Register("rsi", 8)
        self.add(self.rsi)
        self.esi = state.RegisterAlias("rsi", self.rsi, 4, 0)
        self.add(self.esi)
        self.si = state.RegisterAlias("si", self.rsi, 2, 0)
        self.add(self.si)
        self.sil = state.RegisterAlias("sil", self.rsi, 1, 0)
        self.add(self.sil)

        self.rsp = state.Register("rsp", 8)
        self.add(self.rsp)
        self.esp = state.RegisterAlias("rsp", self.rsp, 4, 0)
        self.add(self.esp)
        self.sp = state.RegisterAlias("sp", self.rsp, 2, 0)
        self.add(self.sp)
        self.spl = state.RegisterAlias("spl", self.rsp, 1, 0)
        self.add(self.spl)

        self.rbp = state.Register("rbp", 8)
        self.add(self.rbp)
        self.ebp = state.RegisterAlias("rbp", self.rbp, 4, 0)
        self.add(self.ebp)
        self.bp = state.RegisterAlias("bp", self.rbp, 2, 0)
        self.add(self.bp)
        self.bpl = state.RegisterAlias("bpl", self.rbp, 1, 0)
        self.add(self.bpl)

        # *** Instruction Pointer ***
        self.rip = state.Register("rip", 8)
        self.add(self.rip)
        self.eip = state.RegisterAlias("rip", self.rip, 4, 0)
        self.add(self.eip)
        self.ip = state.RegisterAlias("ip", self.rip, 2, 0)
        self.add(self.ip)

        self.pc = state.RegisterAlias("pc", self.rip, 8, 0)
        self.add(self.pc)

        # *** Flags register ***
        self.rflags = state.Register("rflags", 8)
        self.add(self.rflags)
        self.eflags = state.RegisterAlias("eflags", self.rflags, 4, 0)
        self.add(self.eflags)
        self.flags = state.RegisterAlias("flags", self.rflags, 2, 0)
        self.add(self.flags)

        # *** Segment Registers ***
        # NOTE: These are actually 16 bits
        # However, their representation in different emulators gets weird.
        self.cs = state.Register("cs", 8)
        self.add(self.cs)
        self.ds = state.Register("ds", 8)
        self.add(self.ds)
        self.es = state.Register("es", 8)
        self.add(self.es)
        self.fs = state.Register("fs", 8)
        self.add(self.fs)
        self.gs = state.Register("gs", 8)
        self.add(self.gs)

        # *** Control Registers ***
        self.cr0 = state.Register("cr0", 8)
        self.add(self.cr0)
        self.cr1 = state.Register("cr1", 8)
        self.add(self.cr1)
        self.cr2 = state.Register("cr2", 8)
        self.add(self.cr2)
        self.cr3 = state.Register("cr3", 8)
        self.add(self.cr3)
        self.cr4 = state.Register("cr4", 8)
        self.add(self.cr4)
        self.cr8 = state.Register("cr8", 8)
        self.add(self.cr8)

        # *** Debug Registers ***
        self.dr0 = state.Register("dr0", 8)
        self.add(self.dr0)
        self.dr1 = state.Register("dr1", 8)
        self.add(self.dr1)
        self.dr2 = state.Register("dr2", 8)
        self.add(self.dr2)
        self.dr3 = state.Register("dr3", 8)
        self.add(self.dr3)
        self.dr6 = state.Register("dr6", 8)
        self.add(self.dr6)
        self.dr7 = state.Register("dr7", 8)
        self.add(self.dr7)
        self.dr8 = state.Register("dr8", 8)
        self.add(self.dr8)
        self.dr9 = state.Register("dr9", 8)
        self.add(self.dr9)
        self.dr10 = state.Register("dr10", 8)
        self.add(self.dr10)
        self.dr11 = state.Register("dr11", 8)
        self.add(self.dr11)
        self.dr12 = state.Register("dr12", 8)
        self.add(self.dr12)
        self.dr13 = state.Register("dr13", 8)
        self.add(self.dr13)
        self.dr14 = state.Register("dr14", 8)
        self.add(self.dr14)
        self.dr15 = state.Register("dr15", 8)
        self.add(self.dr15)

        # *** Descriptor Table Registers ***
        self.gdtr = X86MMRRegister("gdtr", 10)
        self.add(self.gdtr)
        self.idtr = X86MMRRegister("idtr", 10)
        self.add(self.idtr)
        self.ldtr = X86MMRRegister("ldtr", 10)
        self.add(self.ldtr)

        # *** Task Register ***
        self.tr = X86MMRRegister("tr", 2)
        self.add(self.tr)

        # *** x87 registers ***
        self.fpr0 = state.Register("fpr0", 10)
        self.add(self.fpr0)
        self.fpr1 = state.Register("fpr1", 10)
        self.add(self.fpr1)
        self.fpr2 = state.Register("fpr2", 10)
        self.add(self.fpr2)
        self.fpr3 = state.Register("fpr3", 10)
        self.add(self.fpr3)
        self.fpr4 = state.Register("fpr4", 10)
        self.add(self.fpr4)
        self.fpr5 = state.Register("fpr5", 10)
        self.add(self.fpr5)
        self.fpr6 = state.Register("fpr6", 10)
        self.add(self.fpr6)
        self.fpr7 = state.Register("fpr7", 10)
        self.add(self.fpr7)

        # x87 Control Register
        self.fctrl = state.Register("fctrl", 2)
        self.add(self.fctrl)
        # x87 Status Register
        self.fstat = state.Register("fstat", 2)
        self.add(self.fstat)
        # x87 Tag Register
        self.ftag = state.Register("ftag", 2)
        self.add(self.ftag)
        # x87 Last Instruction Register
        self.fip = state.Register("fip", 8)
        self.add(self.fip)
        # x87 Last Operand Pointer
        self.fdp = state.Register("fdp", 8)
        self.add(self.fdp)
        # x87 Last Opcode
        self.fop = state.Register("fop", 2)
        self.add(self.fop)

        # NOTE: Docs disagree on the format of fip and fdp.
        # One source describes them as 48-bit offset-plus-segment,
        # the other describes them as 64-bit.
        # There may also be separate segment registers.
        # If you care about the x87 debug info, please feel free to update.

        # *** MMX Registers ***
        # NOTE: The MMX registers are aliases for the low 8 bytes of the x87 registers.
        # The two subsystems cannot be used simultaneously.
        self.mm0 = state.RegisterAlias("mm0", self.fpr0, 8, 0)
        self.add(self.mm0)
        self.mm1 = state.RegisterAlias("mm1", self.fpr1, 8, 0)
        self.add(self.mm1)
        self.mm2 = state.RegisterAlias("mm2", self.fpr2, 8, 0)
        self.add(self.mm2)
        self.mm3 = state.RegisterAlias("mm3", self.fpr3, 8, 0)
        self.add(self.mm3)
        self.mm4 = state.RegisterAlias("mm4", self.fpr4, 8, 0)
        self.add(self.mm4)
        self.mm5 = state.RegisterAlias("mm5", self.fpr5, 8, 0)
        self.add(self.mm5)
        self.mm6 = state.RegisterAlias("mm6", self.fpr6, 8, 0)
        self.add(self.mm6)
        self.mm7 = state.RegisterAlias("mm7", self.fpr7, 8, 0)
        self.add(self.mm7)


class AMD64AVX2(AMD64):
    """AMD64 CPU supporting up to AVX2

    This is our default, since all emulators support up to AVX2,
    and 99.9% of our users won't use the vector extensions.
    """

    platform = platforms.Platform(
        platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
    )

    def __init__(self):
        super().__init__()
        # *** SSE/AVX/AVX2 registers ***
        self.ymm0 = state.Register("ymm0", 32)
        self.add(self.ymm0)
        self.xmm0 = state.RegisterAlias("xmm0", self.ymm0, 16, 0)
        self.add(self.xmm0)

        self.ymm1 = state.Register("ymm1", 32)
        self.add(self.ymm1)
        self.xmm1 = state.RegisterAlias("xmm1", self.ymm1, 16, 0)
        self.add(self.xmm1)

        self.ymm2 = state.Register("ymm2", 32)
        self.add(self.ymm2)
        self.xmm2 = state.RegisterAlias("xmm2", self.ymm2, 16, 0)
        self.add(self.xmm2)

        self.ymm3 = state.Register("ymm3", 32)
        self.add(self.ymm3)
        self.xmm3 = state.RegisterAlias("xmm3", self.ymm3, 16, 0)
        self.add(self.xmm3)

        self.ymm4 = state.Register("ymm4", 32)
        self.add(self.ymm4)
        self.xmm4 = state.RegisterAlias("xmm4", self.ymm4, 16, 0)
        self.add(self.xmm4)

        self.ymm5 = state.Register("ymm5", 32)
        self.add(self.ymm5)
        self.xmm5 = state.RegisterAlias("xmm5", self.ymm5, 16, 0)
        self.add(self.xmm5)

        self.ymm6 = state.Register("ymm6", 32)
        self.add(self.ymm6)
        self.xmm6 = state.RegisterAlias("xmm6", self.ymm6, 16, 0)
        self.add(self.xmm6)

        self.ymm7 = state.Register("ymm7", 32)
        self.add(self.ymm7)
        self.xmm7 = state.RegisterAlias("xmm7", self.ymm7, 16, 0)
        self.add(self.xmm7)

        self.ymm8 = state.Register("ymm8", 32)
        self.add(self.ymm8)
        self.xmm8 = state.RegisterAlias("xmm8", self.ymm8, 16, 0)
        self.add(self.xmm8)

        self.ymm9 = state.Register("ymm9", 32)
        self.add(self.ymm9)
        self.xmm9 = state.RegisterAlias("xmm9", self.ymm9, 16, 0)
        self.add(self.xmm9)

        self.ymm10 = state.Register("ymm10", 32)
        self.add(self.ymm10)
        self.xmm10 = state.RegisterAlias("xmm10", self.ymm10, 16, 0)
        self.add(self.xmm10)

        self.ymm11 = state.Register("ymm11", 32)
        self.add(self.ymm11)
        self.xmm11 = state.RegisterAlias("xmm11", self.ymm11, 16, 0)
        self.add(self.xmm11)

        self.ymm12 = state.Register("ymm12", 32)
        self.add(self.ymm12)
        self.xmm12 = state.RegisterAlias("xmm12", self.ymm12, 16, 0)
        self.add(self.xmm12)

        self.ymm13 = state.Register("ymm13", 32)
        self.add(self.ymm13)
        self.xmm13 = state.RegisterAlias("xmm13", self.ymm13, 16, 0)
        self.add(self.xmm13)

        self.ymm14 = state.Register("ymm14", 32)
        self.add(self.ymm14)
        self.xmm14 = state.RegisterAlias("xmm14", self.ymm14, 16, 0)
        self.add(self.xmm14)

        self.ymm15 = state.Register("ymm15", 32)
        self.add(self.ymm15)
        self.xmm15 = state.RegisterAlias("xmm15", self.ymm15, 16, 0)
        self.add(self.xmm15)


class AMD64AVX512(AMD64):
    """AMD64 CPU supporting up to AVX512"""

    platform = platforms.Platform(
        platforms.Architecture.X86_64_AVX512, platforms.Byteorder.LITTLE
    )

    def __init__(self):
        super().__init__()
        # *** SSE/AVX/AVX2/AVX512 registers ***
        self.zmm0 = state.Register("zmm0", 64)
        self.add(self.zmm0)
        self.ymm0 = state.RegisterAlias("ymm0", self.zmm0, 32, 0)
        self.add(self.ymm0)
        self.xmm0 = state.RegisterAlias("xmm0", self.zmm0, 16, 0)
        self.add(self.xmm0)

        self.zmm1 = state.Register("zmm1", 64)
        self.add(self.zmm1)
        self.ymm1 = state.RegisterAlias("ymm1", self.zmm1, 32, 0)
        self.add(self.ymm1)
        self.xmm1 = state.RegisterAlias("xmm1", self.zmm1, 16, 0)
        self.add(self.xmm1)

        self.zmm2 = state.Register("zmm2", 64)
        self.add(self.zmm2)
        self.ymm2 = state.RegisterAlias("ymm2", self.zmm2, 32, 0)
        self.add(self.ymm2)
        self.xmm2 = state.RegisterAlias("xmm2", self.zmm2, 16, 0)
        self.add(self.xmm2)

        self.zmm3 = state.Register("zmm3", 64)
        self.add(self.zmm3)
        self.ymm3 = state.RegisterAlias("ymm3", self.zmm3, 32, 0)
        self.add(self.ymm3)
        self.xmm3 = state.RegisterAlias("xmm3", self.zmm3, 16, 0)
        self.add(self.xmm3)

        self.zmm4 = state.Register("zmm4", 64)
        self.add(self.zmm4)
        self.ymm4 = state.RegisterAlias("ymm4", self.zmm4, 32, 0)
        self.add(self.ymm4)
        self.xmm4 = state.RegisterAlias("xmm4", self.zmm4, 16, 0)
        self.add(self.xmm4)

        self.zmm5 = state.Register("zmm5", 64)
        self.add(self.zmm5)
        self.ymm5 = state.RegisterAlias("ymm5", self.zmm5, 32, 0)
        self.add(self.ymm5)
        self.xmm5 = state.RegisterAlias("xmm5", self.zmm5, 16, 0)
        self.add(self.xmm5)

        self.zmm6 = state.Register("zmm6", 64)
        self.add(self.zmm6)
        self.ymm6 = state.RegisterAlias("ymm6", self.zmm6, 32, 0)
        self.add(self.ymm6)
        self.xmm6 = state.RegisterAlias("xmm6", self.zmm6, 16, 0)
        self.add(self.xmm6)

        self.zmm7 = state.Register("zmm7", 64)
        self.add(self.zmm7)
        self.ymm7 = state.RegisterAlias("ymm7", self.zmm7, 32, 0)
        self.add(self.ymm7)
        self.xmm7 = state.RegisterAlias("xmm7", self.zmm7, 16, 0)
        self.add(self.xmm7)

        self.zmm8 = state.Register("zmm8", 64)
        self.add(self.zmm8)
        self.ymm8 = state.RegisterAlias("ymm8", self.zmm8, 32, 0)
        self.add(self.ymm8)
        self.xmm8 = state.RegisterAlias("xmm8", self.zmm8, 16, 0)
        self.add(self.xmm8)

        self.zmm9 = state.Register("zmm9", 64)
        self.add(self.zmm9)
        self.ymm9 = state.RegisterAlias("ymm9", self.zmm9, 32, 0)
        self.add(self.ymm9)
        self.xmm9 = state.RegisterAlias("xmm9", self.zmm9, 16, 0)
        self.add(self.xmm9)

        self.zmm10 = state.Register("zmm10", 64)
        self.add(self.zmm10)
        self.ymm10 = state.RegisterAlias("ymm10", self.zmm10, 32, 0)
        self.add(self.ymm10)
        self.xmm10 = state.RegisterAlias("xmm10", self.zmm10, 16, 0)
        self.add(self.xmm10)

        self.zmm11 = state.Register("zmm11", 64)
        self.add(self.zmm11)
        self.ymm11 = state.RegisterAlias("ymm11", self.zmm11, 32, 0)
        self.add(self.ymm11)
        self.xmm11 = state.RegisterAlias("xmm11", self.zmm11, 16, 0)
        self.add(self.xmm11)

        self.zmm12 = state.Register("zmm12", 64)
        self.add(self.zmm12)
        self.ymm12 = state.RegisterAlias("ymm12", self.zmm12, 32, 0)
        self.add(self.ymm12)
        self.xmm12 = state.RegisterAlias("xmm12", self.zmm12, 16, 0)
        self.add(self.xmm12)

        self.zmm13 = state.Register("zmm13", 64)
        self.add(self.zmm13)
        self.ymm13 = state.RegisterAlias("ymm13", self.zmm13, 32, 0)
        self.add(self.ymm13)
        self.xmm13 = state.RegisterAlias("xmm13", self.zmm13, 16, 0)
        self.add(self.xmm13)

        self.zmm14 = state.Register("zmm14", 64)
        self.add(self.zmm14)
        self.ymm14 = state.RegisterAlias("ymm14", self.zmm14, 32, 0)
        self.add(self.ymm14)
        self.xmm14 = state.RegisterAlias("xmm14", self.zmm14, 16, 0)
        self.add(self.xmm14)

        self.zmm15 = state.Register("zmm15", 64)
        self.add(self.zmm15)
        self.ymm15 = state.RegisterAlias("ymm15", self.zmm15, 32, 0)
        self.add(self.ymm15)
        self.xmm15 = state.RegisterAlias("xmm15", self.zmm15, 16, 0)
        self.add(self.xmm15)

        self.zmm16 = state.Register("zmm16", 64)
        self.add(self.zmm16)
        self.ymm16 = state.RegisterAlias("ymm16", self.zmm16, 32, 0)
        self.add(self.ymm16)
        self.xmm16 = state.RegisterAlias("xmm16", self.zmm16, 16, 0)
        self.add(self.xmm16)

        self.zmm17 = state.Register("zmm17", 64)
        self.add(self.zmm17)
        self.ymm17 = state.RegisterAlias("ymm17", self.zmm17, 32, 0)
        self.add(self.ymm17)
        self.xmm17 = state.RegisterAlias("xmm17", self.zmm17, 16, 0)
        self.add(self.xmm17)

        self.zmm18 = state.Register("zmm18", 64)
        self.add(self.zmm18)
        self.ymm18 = state.RegisterAlias("ymm18", self.zmm18, 32, 0)
        self.add(self.ymm18)
        self.xmm18 = state.RegisterAlias("xmm18", self.zmm18, 16, 0)
        self.add(self.xmm18)

        self.zmm19 = state.Register("zmm19", 64)
        self.add(self.zmm19)
        self.ymm19 = state.RegisterAlias("ymm19", self.zmm19, 32, 0)
        self.add(self.ymm19)
        self.xmm19 = state.RegisterAlias("xmm19", self.zmm19, 16, 0)
        self.add(self.xmm19)

        self.zmm20 = state.Register("zmm20", 64)
        self.add(self.zmm20)
        self.ymm20 = state.RegisterAlias("ymm20", self.zmm20, 32, 0)
        self.add(self.ymm20)
        self.xmm20 = state.RegisterAlias("xmm20", self.zmm20, 16, 0)
        self.add(self.xmm20)

        self.zmm21 = state.Register("zmm21", 64)
        self.add(self.zmm21)
        self.ymm21 = state.RegisterAlias("ymm21", self.zmm21, 32, 0)
        self.add(self.ymm21)
        self.xmm21 = state.RegisterAlias("xmm21", self.zmm21, 16, 0)
        self.add(self.xmm21)

        self.zmm22 = state.Register("zmm22", 64)
        self.add(self.zmm22)
        self.ymm22 = state.RegisterAlias("ymm22", self.zmm22, 32, 0)
        self.add(self.ymm22)
        self.xmm22 = state.RegisterAlias("xmm22", self.zmm22, 16, 0)
        self.add(self.xmm22)

        self.zmm23 = state.Register("zmm23", 64)
        self.add(self.zmm23)
        self.ymm23 = state.RegisterAlias("ymm23", self.zmm23, 32, 0)
        self.add(self.ymm23)
        self.xmm23 = state.RegisterAlias("xmm23", self.zmm23, 16, 0)
        self.add(self.xmm23)

        self.zmm24 = state.Register("zmm24", 64)
        self.add(self.zmm24)
        self.ymm24 = state.RegisterAlias("ymm24", self.zmm24, 32, 0)
        self.add(self.ymm24)
        self.xmm24 = state.RegisterAlias("xmm24", self.zmm24, 16, 0)
        self.add(self.xmm24)

        self.zmm25 = state.Register("zmm25", 64)
        self.add(self.zmm25)
        self.ymm25 = state.RegisterAlias("ymm25", self.zmm25, 32, 0)
        self.add(self.ymm25)
        self.xmm25 = state.RegisterAlias("xmm25", self.zmm25, 16, 0)
        self.add(self.xmm25)

        self.zmm26 = state.Register("zmm26", 64)
        self.add(self.zmm26)
        self.ymm26 = state.RegisterAlias("ymm26", self.zmm26, 32, 0)
        self.add(self.ymm26)
        self.xmm26 = state.RegisterAlias("xmm26", self.zmm26, 16, 0)
        self.add(self.xmm26)

        self.zmm27 = state.Register("zmm27", 64)
        self.add(self.zmm27)
        self.ymm27 = state.RegisterAlias("ymm27", self.zmm27, 32, 0)
        self.add(self.ymm27)
        self.xmm27 = state.RegisterAlias("xmm27", self.zmm27, 16, 0)
        self.add(self.xmm27)

        self.zmm28 = state.Register("zmm28", 64)
        self.add(self.zmm28)
        self.ymm28 = state.RegisterAlias("ymm28", self.zmm28, 32, 0)
        self.add(self.ymm28)
        self.xmm28 = state.RegisterAlias("xmm28", self.zmm28, 16, 0)
        self.add(self.xmm28)

        self.zmm29 = state.Register("zmm29", 64)
        self.add(self.zmm29)
        self.ymm29 = state.RegisterAlias("ymm29", self.zmm29, 32, 0)
        self.add(self.ymm29)
        self.xmm29 = state.RegisterAlias("xmm29", self.zmm29, 16, 0)
        self.add(self.xmm29)

        self.zmm30 = state.Register("zmm30", 64)
        self.add(self.zmm30)
        self.ymm30 = state.RegisterAlias("ymm30", self.zmm30, 32, 0)
        self.add(self.ymm30)
        self.xmm30 = state.RegisterAlias("xmm30", self.zmm30, 16, 0)
        self.add(self.xmm30)

        self.zmm31 = state.Register("zmm31", 64)
        self.add(self.zmm31)
        self.ymm31 = state.RegisterAlias("ymm31", self.zmm31, 32, 0)
        self.add(self.ymm31)
        self.xmm31 = state.RegisterAlias("xmm31", self.zmm31, 16, 0)
        self.add(self.xmm31)
