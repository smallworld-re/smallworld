import capstone

from smallworld import platforms

from .bsid import BSIDMemoryReferenceOperand
from .instructions import Instruction, MemoryReferenceOperand


class MIPSInstruction(Instruction):
    angr_arch = "MIPS"
    cs_arch = capstone.CS_ARCH_MIPS
    cs_mode = capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN
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
    platform = platforms.Platform(
        platforms.Architecture.MIPS32, platforms.Byteorder.LITTLE
    )


class MIPS64Instruction(MIPSInstruction):
    angr_arch = "MIPS64"
    cs_mode = capstone.CS_MODE_MIPS64 | capstone.CS_MODE_BIG_ENDIAN
    platform = platforms.Platform(
        platforms.Architecture.MIPS64, platforms.Byteorder.BIG
    )

    def _memory_reference(self, operand) -> MemoryReferenceOperand:
        # Capstone does not expose a per-operand access size for MIPS (the width
        # is encoded in the mnemonic, not the operand), so -- like the MIPS32
        # class above and aarch64 -- we use a fixed pointer-width default. 8 for
        # MIPS64.
        return BSIDMemoryReferenceOperand(
            segment=None,
            base=self._instruction.reg_name(operand.value.mem.base),
            offset=operand.value.mem.disp,
            size=8,
        )


class MIPS64ELInstruction(MIPS64Instruction):
    cs_mode = capstone.CS_MODE_MIPS64
    platform = platforms.Platform(
        platforms.Architecture.MIPS64, platforms.Byteorder.LITTLE
    )
