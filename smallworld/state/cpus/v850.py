from ... import platforms, state
from ...platforms.defs.v850 import (
    V850_GENERAL_REGISTERS,
    V850_NAMED_REGISTERS,
    V850_PROGRAM_COUNTER_REGISTER,
    V850_SYSTEM_REGISTERS,
)
from . import cpu


class V850(cpu.CPU):
    """CPU for V850E1, V850E2 and V850E2M."""

    platform = platforms.Platform(
        platforms.Architecture.V850, platforms.Byteorder.LITTLE
    )

    def __init__(self):
        super().__init__()

        for name in V850_GENERAL_REGISTERS:
            register = state.Register(name, 4)
            setattr(self, name, register)
            self.add(register)

        for name, number in V850_NAMED_REGISTERS.items():
            alias = state.RegisterAlias(number, getattr(self, name), 4, 0)
            setattr(self, number, alias)
            self.add(alias)

        self.pc = state.Register(V850_PROGRAM_COUNTER_REGISTER, 4)
        self.add(self.pc)

        for name in V850_SYSTEM_REGISTERS:
            register = state.Register(name, 4)
            setattr(self, name, register)
            self.add(register)
