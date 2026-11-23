import capstone

from smallworld import platforms

from .bsid import BSIDMemoryReferenceOperand
from .instructions import Instruction, MemoryReferenceOperand


class AArch64Instruction(Instruction):
    angr_arch = "AARCH64"
    cs_arch = capstone.CS_ARCH_ARM64
    cs_mode = capstone.CS_MODE_ARM
    platform = platforms.Platform(
        platforms.Architecture.AARCH64, platforms.Byteorder.LITTLE
    )

    def _memory_reference(self, operand) -> MemoryReferenceOperand:
        # TODO: AArch64 operands have no size; what should it be?
        # I suspect it's always the same; is it always 64-bit?
        return BSIDMemoryReferenceOperand(
            segment=None,
            base=self._instruction.reg_name(operand.value.mem.base),
            index=self._instruction.reg_name(operand.value.mem.index),
            offset=operand.value.mem.disp,
            size=8,
        )


class AArch64BEInstruction(AArch64Instruction):
    # AArch64 instructions are little-endian even when data is big-endian,
    # so these decode as their little-endian counterparts do.
    platform = platforms.Platform(
        platforms.Architecture.AARCH64, platforms.Byteorder.BIG
    )


class AArch64V85AInstruction(AArch64Instruction):
    platform = platforms.Platform(
        platforms.Architecture.AARCH64_V8_5A, platforms.Byteorder.LITTLE
    )


class AArch64V85ABEInstruction(AArch64BEInstruction):
    platform = platforms.Platform(
        platforms.Architecture.AARCH64_V8_5A, platforms.Byteorder.BIG
    )
