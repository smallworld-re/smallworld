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


class PPC64Instruction(PPC32Instruction):
    angr_arch = "PPC64"
    cs_mode = capstone.CS_MODE_64 | capstone.CS_MODE_BIG_ENDIAN
    platform = platforms.Platform(
        platforms.Architecture.POWERPC64, platforms.Byteorder.BIG
    )

    def _memory_reference(self, operand) -> MemoryReferenceOperand:
        # Capstone does not expose a per-operand access size for PowerPC (the
        # width is encoded in the mnemonic, not the operand), so -- like the
        # PPC32 class above -- we use a fixed pointer-width default. 8 for PPC64.
        return BSIDMemoryReferenceOperand(
            segment=None,
            base=self._instruction.reg_name(operand.value.mem.base),
            offset=operand.value.mem.disp,
            size=8,
        )
