import capstone

from smallworld import platforms

from .bsid import BSIDMemoryReferenceOperand
from .instructions import Instruction, MemoryReferenceOperand


class PPC32Instruction(Instruction):
    angr_arch = "PPC"
    cs_arch = capstone.CS_ARCH_PPC
    cs_mode = capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN
    platform = platforms.Platform(
        platforms.Architecture.POWERPC32, platforms.Byteorder.BIG
    )

    def _memory_reference(self, operand) -> MemoryReferenceOperand:
        return BSIDMemoryReferenceOperand(
            segment=None,
            base=self._instruction.reg_name(operand.value.mem.base),
            offset=operand.value.mem.disp,
            size=4,
        )
