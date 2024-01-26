import random
import typing

from .. import state


class i386CPUState(state.State):
    """i386 CPU state model.

    Arguments:
        stackaddress (int): Address of the stack - if omitted, the stack
            address is randomized in high memory space.
        stacksize (int): Size of the stack. This must be a multiple of the page
            size.
    """

    BITS = 32
    PAGE_SIZE = 0x1000
    STACK_POINTER = "esp"

    def setup(
        self,
        stackaddress: typing.Optional[int] = None,
        stacksize: int = 0x4000,
    ) -> None:
        """Common setup for this and subclasses."""

        if stacksize % self.PAGE_SIZE:
            raise ValueError("stacksize must be a multiple of the page size")

        if stackaddress is None:
            minimum = 0xFF
            minimum = minimum << (self.BITS - minimum.bit_length())

            maximum = (1 << self.BITS) - 1
            maximum = maximum - stacksize

            stackaddress = random.randint(
                minimum // self.PAGE_SIZE, maximum // self.PAGE_SIZE
            )
            stackaddress = stackaddress * self.PAGE_SIZE

        self.stack = state.Memory(stackaddress, stacksize)

        getattr(self, self.STACK_POINTER).set(stackaddress)

    def __init__(self, *args, **kwargs):
        self.eax = state.Register("eax")
        self.ax = state.RegisterAlias("ax", self.eax, width=2)
        self.al = state.RegisterAlias("al", self.eax, width=1)
        self.ah = state.RegisterAlias("ah", self.eax, width=1, offset=1)

        self.ebx = state.Register("ebx")
        self.bx = state.RegisterAlias("bx", self.ebx, width=2)
        self.bl = state.RegisterAlias("bl", self.ebx, width=1)
        self.bh = state.RegisterAlias("bh", self.ebx, width=1, offset=1)

        self.ecx = state.Register("ecx")
        self.cx = state.RegisterAlias("cx", self.ecx, width=2)
        self.cl = state.RegisterAlias("cl", self.ecx, width=1)
        self.ch = state.RegisterAlias("ch", self.ecx, width=1, offset=1)

        self.edx = state.Register("edx")
        self.dx = state.RegisterAlias("dx", self.edx, width=2)
        self.dl = state.RegisterAlias("dl", self.edx, width=1)
        self.dh = state.RegisterAlias("dh", self.edx, width=1, offset=1)

        self.esi = state.Register("esi")
        self.si = state.RegisterAlias("si", self.esi, width=2)
        self.sil = state.RegisterAlias("sil", self.esi, width=1)

        self.edi = state.Register("edi")
        self.di = state.RegisterAlias("di", self.edi, width=2)
        self.dil = state.RegisterAlias("dil", self.edi, width=1)

        self.ebp = state.Register("ebp")
        self.bp = state.RegisterAlias("bp", self.ebp, width=2)
        self.bpl = state.RegisterAlias("bpl", self.ebp, width=1)

        self.esp = state.Register("esp")
        self.sp = state.RegisterAlias("sp", self.esp, width=2)
        self.spl = state.RegisterAlias("spl", self.esp, width=1)

        self.eip = state.Register("eip")
        self.ip = state.RegisterAlias("ip", self.eip, width=2)

        self.cs = state.Register("cs")
        self.ds = state.Register("ds")
        self.es = state.Register("es")
        self.fs = state.Register("fs")
        self.gs = state.Register("gs")

        self.eflags = state.Register("eflags")
        self.flags = state.RegisterAlias("flags", self.eflags, width=2)

        self.cr0 = state.Register("cr0")
        self.cr1 = state.Register("cr1")
        self.cr2 = state.Register("cr2")
        self.cr3 = state.Register("cr3")
        self.cr4 = state.Register("cr4")

        self.setup(*args, **kwargs)
