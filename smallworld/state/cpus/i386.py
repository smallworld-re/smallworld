import typing

from ... import platforms
from .. import state
from ..x86_registers import X86MMRRegister
from . import cpu


class I386(cpu.CPU):
    """i386 CPU state model."""

    platform = platforms.Platform(
        platforms.Architecture.X86_32, platforms.Byteorder.LITTLE
    )

    _GENERAL_PURPOSE_REGS = ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp"]

    def get_general_purpose_registers(self) -> typing.List[str]:
        return self._GENERAL_PURPOSE_REGS

    def __init__(self):
        super().__init__()
        # *** General Purpose Registers ***
        self.eax = state.Register("eax", 4)
        self.add(self.eax)
        self.ax = state.RegisterAlias("ax", self.eax, 2, 0)
        self.add(self.ax)
        self.al = state.RegisterAlias("al", self.eax, 1, 0)
        self.add(self.al)
        self.ah = state.RegisterAlias("ah", self.eax, 1, 1)
        self.add(self.ah)

        self.ebx = state.Register("ebx", 4)
        self.add(self.ebx)
        self.bx = state.RegisterAlias("bx", self.ebx, 2, 0)
        self.add(self.bx)
        self.bl = state.RegisterAlias("bl", self.ebx, 1, 0)
        self.add(self.bl)
        self.bh = state.RegisterAlias("bh", self.ebx, 1, 1)
        self.add(self.bh)

        self.ecx = state.Register("ecx", 4)
        self.add(self.ecx)
        self.cx = state.RegisterAlias("cx", self.ecx, 2, 0)
        self.add(self.cx)
        self.cl = state.RegisterAlias("cl", self.ecx, 1, 0)
        self.add(self.cl)
        self.ch = state.RegisterAlias("ch", self.ecx, 1, 1)
        self.add(self.ch)

        self.edx = state.Register("edx", 4)
        self.add(self.edx)
        self.dx = state.RegisterAlias("dx", self.edx, 2, 0)
        self.add(self.dx)
        self.dl = state.RegisterAlias("dl", self.edx, 1, 0)
        self.add(self.dl)
        self.dh = state.RegisterAlias("dh", self.edx, 1, 1)
        self.add(self.dh)

        self.esi = state.Register("esi", 4)
        self.add(self.esi)
        self.si = state.RegisterAlias("si", self.esi, 2, 0)
        self.add(self.si)
        self.sil = state.RegisterAlias("sil", self.esi, 1, 0)
        self.add(self.sil)

        self.edi = state.Register("edi", 4)
        self.add(self.edi)
        self.di = state.RegisterAlias("di", self.edi, 2, 0)
        self.add(self.di)
        self.dil = state.RegisterAlias("dil", self.edi, 1, 0)
        self.add(self.dil)

        self.ebp = state.Register("ebp", 4)
        self.add(self.ebp)
        self.bp = state.RegisterAlias("bp", self.ebp, 2, 0)
        self.add(self.bp)
        self.bpl = state.RegisterAlias("bpl", self.ebp, 1, 0)
        self.add(self.bpl)

        self.esp = state.Register("esp", 4)
        self.add(self.esp)
        self.sp = state.RegisterAlias("sp", self.esp, 2, 0)
        self.add(self.sp)
        self.spl = state.RegisterAlias("spl", self.esp, 1, 0)
        self.add(self.spl)

        # *** Instruction Pointer ***
        self.eip = state.Register("eip", 4)
        self.add(self.eip)
        self.ip = state.RegisterAlias("ip", self.eip, 2, 0)
        self.add(self.ip)

        self.pc = state.RegisterAlias("pc", self.eip, 4, 0)
        self.add(self.pc)

        # *** Segment Registers ***
        self.cs = state.Register("cs", 2)
        self.add(self.cs)
        self.ss = state.Register("ss", 2)
        self.add(self.ss)
        self.ds = state.Register("ds", 2)
        self.add(self.ds)
        self.es = state.Register("es", 2)
        self.add(self.es)
        self.fs = state.Register("fs", 2)
        self.add(self.fs)
        self.gs = state.Register("gs", 2)
        self.add(self.gs)

        # *** Flags Registers ***
        self.eflags = state.Register("eflags", 4)
        self.add(self.eflags)
        self.flags = state.RegisterAlias("flags", self.eflags, 2)
        self.add(self.flags)

        # *** Control Registers ***
        self.cr0 = state.Register("cr0", 4)
        self.add(self.cr0)
        self.cr1 = state.Register("cr1", 4)
        self.add(self.cr1)
        self.cr2 = state.Register("cr2", 4)
        self.add(self.cr2)
        self.cr3 = state.Register("cr3", 4)
        self.add(self.cr3)
        self.cr4 = state.Register("cr4", 4)
        self.add(self.cr4)
        # NOTE: I've got conflicting reports whether cr8 exists in i386.
        self.cr8 = state.Register("cr8", 4)
        self.add(self.cr8)

        # *** Debug Registers ***
        self.dr0 = state.Register("dr0", 4)
        self.add(self.dr0)
        self.dr1 = state.Register("dr1", 4)
        self.add(self.dr1)
        self.dr2 = state.Register("dr2", 4)
        self.add(self.dr2)
        self.dr3 = state.Register("dr3", 4)
        self.add(self.dr3)
        self.dr6 = state.Register("dr6", 4)
        self.add(self.dr6)
        self.dr7 = state.Register("dr7", 4)
        self.add(self.dr7)

        # *** Descriptor Table Registers
        # NOTE: Yes, this is 6 bytes; 2 byte segment selector plus 4 byte offset
        self.gdtr = X86MMRRegister("gdtr", 6)
        self.add(self.gdtr)
        self.idtr = X86MMRRegister("idtr", 6)
        self.add(self.idtr)
        self.ldtr = X86MMRRegister("ldtr", 6)
        self.add(self.ldtr)

        # *** Task Register ***
        # NOTE: Yes, this is 6 bytes; 2 byte segment selector plus 4 byte offset
        self.tr = X86MMRRegister("tr", 6)
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

        # *** SSE Registers ***
        self.xmm0 = state.Register("xmm0", 16)
        self.add(self.xmm0)
        self.xmm1 = state.Register("xmm1", 16)
        self.add(self.xmm1)
        self.xmm2 = state.Register("xmm2", 16)
        self.add(self.xmm2)
        self.xmm3 = state.Register("xmm3", 16)
        self.add(self.xmm3)
        self.xmm4 = state.Register("xmm4", 16)
        self.add(self.xmm4)
        self.xmm5 = state.Register("xmm5", 16)
        self.add(self.xmm5)
        self.xmm6 = state.Register("xmm6", 16)
        self.add(self.xmm6)
        self.xmm7 = state.Register("xmm7", 16)
        self.add(self.xmm7)
