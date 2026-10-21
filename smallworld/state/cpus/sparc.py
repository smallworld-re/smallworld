from ... import platforms, state
from ...platforms.defs.sparc import (
    SPARC_MULTIPLY_STEP_REGISTER,
    SPARC_NEXT_PROGRAM_COUNTER_REGISTER,
    SPARC_PROGRAM_COUNTER_REGISTER,
    SPARC_REGISTER_ALIASES,
    SPARC_WINDOW_REGISTERS,
)
from . import cpu


class SPARC32(cpu.CPU):
    """CPU for 32-bit SPARC V8, big-endian.

    Only the registers visible through the current register window are
    modeled; the windows saved by callers are not part of this state.
    """

    platform = platforms.Platform(
        platforms.Architecture.SPARC32, platforms.Byteorder.BIG
    )

    def __init__(self):
        super().__init__()

        for name in SPARC_WINDOW_REGISTERS:
            register = state.Register(name, 4)
            setattr(self, name, register)
            self.add(register)

        for alias, parent in SPARC_REGISTER_ALIASES.items():
            register = state.RegisterAlias(alias, getattr(self, parent), 4, 0)
            setattr(self, alias, register)
            self.add(register)

        self.pc = state.Register(SPARC_PROGRAM_COUNTER_REGISTER, 4)
        self.add(self.pc)
        self.npc = state.Register(SPARC_NEXT_PROGRAM_COUNTER_REGISTER, 4)
        self.add(self.npc)
        self.y = state.Register(SPARC_MULTIPLY_STEP_REGISTER, 4)
        self.add(self.y)
