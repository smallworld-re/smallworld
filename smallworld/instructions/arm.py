import typing

import capstone

from smallworld import platforms

from .bsid import BSIDMemoryReferenceOperand
from .instructions import Instruction, MemoryReferenceOperand


class ARMInstruction(Instruction):
    angr_arch = "ARM"
    cs_arch = capstone.CS_ARCH_ARM
    cs_mode = capstone.CS_MODE_ARM
    # ARM-mode use/def via the pcode analysis (validated by
    # tests/use_def/corpus_arm32.json). The Thumb subclass overrides
    # this back to None -- analyze_bytes disassembles in the language's
    # default (ARM) mode, so Thumb bytes would be mis-decoded; Thumb
    # falls back to the Capstone implementation. Annotated Optional[str]
    # (rather than letting the string literal narrow it to str) so that
    # None override typechecks.
    ghidra_lang: typing.Optional[str] = "ARM:LE:32:v8"

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
    # Thumb has no validated pcode path here; use the Capstone fallback.
    ghidra_lang = None
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
