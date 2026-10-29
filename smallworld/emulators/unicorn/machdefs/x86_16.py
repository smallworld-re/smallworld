import typing

import unicorn

from ....platforms import Architecture, Byteorder
from .i386 import i386MachineDef


class X86RealModeMachineDef(i386MachineDef):
    """Unicorn machine definition for 16-bit x86 in real mode.

    Unicorn already treats addresses as linear in 16-bit mode: emu_start()
    takes a linear start and stop address and sets ip from cs, and code
    hooks report linear addresses. Its ip and eip registers hold only the
    offset into the code segment, so `pc` is computed from ip and cs.
    """

    arch = Architecture.X86_16
    byteorder = Byteorder.LITTLE

    uc_mode = unicorn.UC_MODE_16

    _registers = {
        **i386MachineDef._registers,
        "pc": unicorn.x86_const.UC_X86_REG_IP,
    }

    def pc_from_engine(self, engine: typing.Any, value: int) -> int:
        return (engine.reg_read(unicorn.x86_const.UC_X86_REG_CS) << 4) + value

    def pc_to_engine(self, engine: typing.Any, pc: int) -> int:
        base = engine.reg_read(unicorn.x86_const.UC_X86_REG_CS) << 4
        offset = pc - base
        if not 0 <= offset <= 0xFFFF:
            raise ValueError(
                f"pc {pc:#x} is outside the code segment at {base:#x}; set cs first"
            )
        return offset
