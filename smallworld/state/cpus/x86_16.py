from ... import emulators, platforms
from .. import state
from .i386 import I386


class X86RealMode(I386):
    """16-bit x86 real-mode CPU state model.

    The registers are the 80386's, but ``pc`` is the linear address of the
    next instruction (``cs * 16 + ip``) rather than an alias of ``eip``. Set
    ``pc`` and the segment registers. On Unicorn, ``ip`` and ``eip`` follow
    from them; angr and Ghidra have no ``eip``, so leave ``ip`` and ``eip``
    unset there.

    The segment registers start at 0, so a harness that sets nothing else
    runs in the first 64 KiB with every segment overlapping. Every memory
    access goes through a segment register, so leaving them unset would leave
    every address symbolic on angr.
    """

    platform = platforms.Platform(
        platforms.Architecture.X86_16, platforms.Byteorder.LITTLE
    )

    def __init__(self):
        super().__init__()
        self.discard(self.pc)
        self.pc = state.Register("pc", 4)
        self.add(self.pc)

        for segment in (self.cs, self.ds, self.es, self.fs, self.gs, self.ss):
            segment.set(0)

    def apply(self, emulator: emulators.Emulator) -> None:
        # The emulator derives ip from pc and cs, so pc goes last: after the
        # segment registers it depends on, and after any extracted ip or eip
        # it supersedes.
        for stateful in self:
            if stateful is not self.pc:
                stateful.apply(emulator)
        self.pc.apply(emulator)
