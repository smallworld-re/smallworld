from ... import platforms, state
from . import cpu


class TriCore(cpu.CPU):
    """CPU for TriCore, little-endian."""

    platform = platforms.Platform(
        platforms.Architecture.TRICORE, platforms.Byteorder.LITTLE
    )

    def __init__(self):
        super().__init__()

        for prefix in ("a", "d"):
            for i in range(0, 16):
                register = state.Register(f"{prefix}{i}", 4)
                setattr(self, f"{prefix}{i}", register)
                self.add(register)

        self.sp = state.RegisterAlias("sp", self.a10, 4, 0)
        self.add(self.sp)
        self.ra = state.RegisterAlias("ra", self.a11, 4, 0)
        self.add(self.ra)
        self.lr = state.RegisterAlias("lr", self.a11, 4, 0)
        self.add(self.lr)

        self.pc = state.Register("pc", 4)
        self.add(self.pc)
        self.psw = state.Register("psw", 4)
        self.add(self.psw)
