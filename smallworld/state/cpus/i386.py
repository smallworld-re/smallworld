import typing

from ... import platforms
from .. import state
from . import cpu
from ...arch import i386_arch


class I386(cpu.CPU):
    """i386 CPU state model."""

    platform = platforms.Platform(
        platforms.Architecture.X86_32, platforms.Byteorder.LITTLE
    )

    _GENERAL_PURPOSE_REGS = ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp"]

    platform = platforms.Platform(
        platforms.Architecture.X86_32, platforms.Byteorder.LITTLE
    )

    arch_info = i386_arch.info

    def get_general_purpose_registers(self) -> typing.List[str]:
        return self._GENERAL_PURPOSE_REGS


    # this should be unnecessary (?) when i386 cpu has been implemented.
    #def __init__(self):
    #    # use arch_info to create all these regs and reg aliases...
    #    super(i386.I386, self).__init__()

        
        

    # def __init__(self):
    #     self.eax = state.Register("eax")
    #     self.ax = state.RegisterAlias("ax", self.eax, size=2)
    #     self.al = state.RegisterAlias("al", self.eax, size=1)
    #     self.ah = state.RegisterAlias("ah", self.eax, size=1, offset=1)

    #     self.ebx = state.Register("ebx")
    #     self.bx = state.RegisterAlias("bx", self.ebx, size=2)
    #     self.bl = state.RegisterAlias("bl", self.ebx, size=1)
    #     self.bh = state.RegisterAlias("bh", self.ebx, size=1, offset=1)

    #     self.ecx = state.Register("ecx")
    #     self.cx = state.RegisterAlias("cx", self.ecx, size=2)
    #     self.cl = state.RegisterAlias("cl", self.ecx, size=1)
    #     self.ch = state.RegisterAlias("ch", self.ecx, size=1, offset=1)

    #     self.edx = state.Register("edx")
    #     self.dx = state.RegisterAlias("dx", self.edx, size=2)
    #     self.dl = state.RegisterAlias("dl", self.edx, size=1)
    #     self.dh = state.RegisterAlias("dh", self.edx, size=1, offset=1)

    #     self.esi = state.Register("esi")
    #     self.si = state.RegisterAlias("si", self.esi, size=2)
    #     self.sil = state.RegisterAlias("sil", self.esi, size=1)

    #     self.edi = state.Register("edi")
    #     self.di = state.RegisterAlias("di", self.edi, size=2)
    #     self.dil = state.RegisterAlias("dil", self.edi, size=1)

    #     self.ebp = state.Register("ebp")
    #     self.bp = state.RegisterAlias("bp", self.ebp, size=2)
    #     self.bpl = state.RegisterAlias("bpl", self.ebp, size=1)

    #     self.esp = state.Register("esp")
    #     self.sp = state.RegisterAlias("sp", self.esp, size=2)
    #     self.spl = state.RegisterAlias("spl", self.esp, size=1)

    #     self.eip = state.Register("eip")
    #     self.ip = state.RegisterAlias("ip", self.eip, size=2)

    #     self.cs = state.Register("cs")
    #     self.ds = state.Register("ds")
    #     self.es = state.Register("es")
    #     self.fs = state.Register("fs")
    #     self.gs = state.Register("gs")

    #     self.eflags = state.Register("eflags")
    #     self.flags = state.RegisterAlias("flags", self.eflags, size=2)

    #     self.cr0 = state.Register("cr0")
    #     self.cr1 = state.Register("cr1")
    #     self.cr2 = state.Register("cr2")
    #     self.cr3 = state.Register("cr3")
    #     self.cr4 = state.Register("cr4")
