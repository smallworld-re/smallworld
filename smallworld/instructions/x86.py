import capstone

from smallworld import platforms

from .bsid import x86BSIDMemoryReferenceOperand
from .instructions import Instruction, MemoryReferenceOperand


class x86Instruction(Instruction):
    word_size = 4
    angr_arch = "X86"
    cs_arch = capstone.CS_ARCH_X86
    cs_mode = capstone.CS_MODE_32
    ghidra_lang = "x86:LE:32:default"
    sp = "esp"
    platform = platforms.Platform(
        platforms.Architecture.X86_32, platforms.Byteorder.LITTLE
    )

    def _memory_reference(self, segment, base, index, scale, offset, size):
        return x86BSIDMemoryReferenceOperand(
            segment=segment,
            base=base,
            index=index,
            scale=scale,
            offset=offset,
            size=size,
        )

    # operand is a capstone operand
    def _memory_reference_operand(self, operand) -> MemoryReferenceOperand:
        return self._memory_reference(
            self._instruction.reg_name(operand.value.mem.segment),
            self._instruction.reg_name(operand.value.mem.base),
            self._instruction.reg_name(operand.value.mem.index),
            operand.value.mem.scale,
            operand.value.mem.disp,
            operand.size,
        )


class AMD64Instruction(x86Instruction):
    angr_arch = "AMD64"
    cs_mode = capstone.CS_MODE_64
    ghidra_lang = "x86:LE:64:default"
    sp = "rsp"
    word_size = 8
    platform = platforms.Platform(
        platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
    )
