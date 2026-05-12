from ... import platforms, state
from ...platforms.defs.tricore import (
    TRICORE_PROGRAM_COUNTER_REGISTER,
    TRICORE_REGISTER_ALIASES,
    TRICORE_STATUS_REGISTER,
)
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

        for alias, parent in TRICORE_REGISTER_ALIASES.items():
            register = state.RegisterAlias(alias, getattr(self, parent), 4, 0)
            setattr(self, alias, register)
            self.add(register)

        self.pc = state.Register(TRICORE_PROGRAM_COUNTER_REGISTER, 4)
        self.add(self.pc)
        self.psw = state.Register(TRICORE_STATUS_REGISTER, 4)
        self.add(self.psw)
