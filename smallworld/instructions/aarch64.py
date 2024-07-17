import capstone

from .bsid import BSIDMemoryReferenceOperand
from .instructions import Instruction, MemoryReferenceOperand


class AArch64Instruction(Instruction):
    angr_arch = "AARCH64"
    cs_arch = capstone.CS_ARCH_ARM64
    cs_mode = capstone.CS_MODE_ARM

    def _memory_reference(self, operand) -> MemoryReferenceOperand:
        # TODO: AArch64 operands have no size; what should it be?
        # I suspect it's always the same; is it always 64-bit?
        return BSIDMemoryReferenceOperand(
            base=self._instruction.reg_name(operand.value.mem.base),
            index=self._instruction.reg_name(operand.value.mem.index),
            offset=operand.value.mem.disp,
            size=8,
        )
