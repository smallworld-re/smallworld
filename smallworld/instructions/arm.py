import capstone

from smallworld import platforms

from .bsid import BSIDMemoryReferenceOperand
from .instructions import Instruction, MemoryReferenceOperand


class ARMInstruction(Instruction):
    angr_arch = "ARM"
    cs_arch = capstone.CS_ARCH_ARM
    cs_mode = capstone.CS_MODE_ARM

    def _memory_reference(self, operand) -> MemoryReferenceOperand:
        return BSIDMemoryReferenceOperand(
            segment=None,
            base=self._instruction.reg_name(operand.value.mem.base),
            index=self._instruction.reg_name(operand.value.mem.index),
            offset=operand.value.mem.disp,
            size=4,
        )


class ARMV5TInstruction(ARMInstruction):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V5T, platforms.Byteorder.LITTLE
    )


class ARMV6MInstruction(ARMInstruction):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V6M, platforms.Byteorder.LITTLE
    )


class ARMV6MThumbInstruction(ARMInstruction):
    cs_mode = capstone.CS_MODE_THUMB
    # ARMv6MThumb's PlatformDef deliberately carries the ARM-mode language
    # id ("ARM:LE:32:v6") because Ghidra reaches Thumb through the TMode
    # context register within that same SLEIGH language. The p-code use/def
    # analysis disassembles with the language's default context, i.e. ARM,
    # so Thumb bytes decode as a valid but entirely unrelated ARM
    # instruction. A 16-bit Thumb instruction is caught by the length
    # cross-check in _pcode_use_def, but a 32-bit Thumb-2 one is four bytes
    # either way and would pass it while being wrong, so refuse outright.
    supports_pcode_use_def = False
    platform = platforms.Platform(
        platforms.Architecture.ARM_V6M_THUMB, platforms.Byteorder.LITTLE
    )


class ARMV7AInstruction(ARMInstruction):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V7A, platforms.Byteorder.LITTLE
    )


class ARMV7MInstruction(ARMInstruction):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V7M, platforms.Byteorder.LITTLE
    )


class ARMV7RInstruction(ARMInstruction):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V7R, platforms.Byteorder.LITTLE
    )
