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


class ARMV4Instruction(ARMInstruction):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V4, platforms.Byteorder.LITTLE
    )


class ARMV4TInstruction(ARMInstruction):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V4T, platforms.Byteorder.LITTLE
    )


class ARMV5TInstruction(ARMInstruction):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V5T, platforms.Byteorder.LITTLE
    )


class ARMBEInstruction(ARMInstruction):
    # BE32: instructions are big-endian, like data.
    cs_mode = capstone.CS_MODE_ARM | capstone.CS_MODE_BIG_ENDIAN


class ARMV4BEInstruction(ARMBEInstruction):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V4, platforms.Byteorder.BIG
    )


class ARMV4TBEInstruction(ARMBEInstruction):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V4T, platforms.Byteorder.BIG
    )


class ARMV5TBEInstruction(ARMBEInstruction):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V5T, platforms.Byteorder.BIG
    )


class ARMV6KInstruction(ARMInstruction):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V6K, platforms.Byteorder.LITTLE
    )


class ARMV6MInstruction(ARMInstruction):
    # M-profile is Thumb-only.
    cs_mode = capstone.CS_MODE_THUMB
    platform = platforms.Platform(
        platforms.Architecture.ARM_V6M, platforms.Byteorder.LITTLE
    )


class ARMV7AInstruction(ARMInstruction):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V7A, platforms.Byteorder.LITTLE
    )


class ARMV7MInstruction(ARMInstruction):
    # M-profile is Thumb-only.
    cs_mode = capstone.CS_MODE_THUMB
    platform = platforms.Platform(
        platforms.Architecture.ARM_V7M, platforms.Byteorder.LITTLE
    )


class ARMV7EMInstruction(ARMInstruction):
    # M-profile is Thumb-only.
    cs_mode = capstone.CS_MODE_THUMB
    platform = platforms.Platform(
        platforms.Architecture.ARM_V7EM, platforms.Byteorder.LITTLE
    )


class ARMV7RInstruction(ARMInstruction):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V7R, platforms.Byteorder.LITTLE
    )


class ARMV8AInstruction(ARMInstruction):
    cs_mode = capstone.CS_MODE_ARM | capstone.CS_MODE_V8
    platform = platforms.Platform(
        platforms.Architecture.ARM_V8A, platforms.Byteorder.LITTLE
    )


class ARMV8RInstruction(ARMInstruction):
    cs_mode = capstone.CS_MODE_ARM | capstone.CS_MODE_V8
    platform = platforms.Platform(
        platforms.Architecture.ARM_V8R, platforms.Byteorder.LITTLE
    )


class ARMV8MInstruction(ARMInstruction):
    # M-profile is Thumb-only.
    cs_mode = capstone.CS_MODE_THUMB | capstone.CS_MODE_V8
    platform = platforms.Platform(
        platforms.Architecture.ARM_V8M, platforms.Byteorder.LITTLE
    )


# BE8: instructions are little-endian, so these decode as their
# little-endian counterparts do.


class ARMV6KBEInstruction(ARMV6KInstruction):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V6K, platforms.Byteorder.BIG
    )


class ARMV7ABEInstruction(ARMV7AInstruction):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V7A, platforms.Byteorder.BIG
    )


class ARMV7RBEInstruction(ARMV7RInstruction):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V7R, platforms.Byteorder.BIG
    )


class ARMV8ABEInstruction(ARMV8AInstruction):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V8A, platforms.Byteorder.BIG
    )


class ARMV8RBEInstruction(ARMV8RInstruction):
    platform = platforms.Platform(
        platforms.Architecture.ARM_V8R, platforms.Byteorder.BIG
    )
