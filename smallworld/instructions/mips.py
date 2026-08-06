import capstone

from smallworld import platforms

from .bsid import BSIDMemoryReferenceOperand
from .instructions import Instruction, MemoryReferenceOperand


class MIPSInstruction(Instruction):
    angr_arch = "MIPS"
    cs_arch = capstone.CS_ARCH_MIPS
    cs_mode = capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN
    ghidra_lang = "MIPS:BE:32:default"
    platform = platforms.Platform(
        platforms.Architecture.MIPS32, platforms.Byteorder.BIG
    )

    def _memory_reference(self, operand) -> MemoryReferenceOperand:
        return BSIDMemoryReferenceOperand(
            segment=None,
            base=self._instruction.reg_name(operand.value.mem.base),
            offset=operand.value.mem.disp,
            size=4,
        )


class MIPSELInstruction(MIPSInstruction):
    cs_mode = capstone.CS_MODE_MIPS32
    ghidra_lang = "MIPS:LE:32:default"
    platform = platforms.Platform(
        platforms.Architecture.MIPS32, platforms.Byteorder.LITTLE
    )
