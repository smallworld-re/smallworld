import capstone

from .bsid import BSIDMemoryReferenceOperand
from .instructions import Instruction, MemoryReferenceOperand


class ARMInstruction(Instruction):
    angr_arch = "ARM"
    cs_arch = capstone.CS_ARCH_ARM
    cs_mode = capstone.CS_MODE_ARM

    def _memory_reference(self, operand) -> MemoryReferenceOperand:
        return BSIDMemoryReferenceOperand(
            base=self._instruction.reg_name(operand.value.mem.base),
            index=self._instruction.reg_name(operand.value.mem.index),
            offset=operand.value.mem.disp,
            size=4,
        )
