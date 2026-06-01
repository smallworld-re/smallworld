import typing

import capstone

from smallworld import platforms

from .bsid import x86BSIDMemoryReferenceOperand
from .instructions import Instruction, MemoryReferenceOperand, Operand, RegisterOperand

from .instr_use_def import analyze_bytes

class x86Instruction(Instruction):
    word_size = 4
    angr_arch = "X86"
    cs_arch = capstone.CS_ARCH_X86
    cs_mode = capstone.CS_MODE_32
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

    @property
    def reads(self) -> typing.Set[Operand]:
        """Registers and memory references read by this instruction.

        This is a list of string register names and dictionary memory reference
        specifications (i.e., in the form `base + scale * index + offset`).
        """
        r = analyze_bytes(self.instruction, "x86:LE:32:default", self.address)
        return r[0]['use']

    @property
    def writes(self) -> typing.Set[Operand]:
        """Registers and memory references written by this instruction.

        Same format as `reads`.
        """
        r = analyze_bytes(self.instruction, "x86:LE:32:default", self.address)
        return r[0]['def']



class AMD64Instruction(x86Instruction):
    angr_arch = "AMD64"
    cs_mode = capstone.CS_MODE_64
    sp = "rsp"
    word_size = 8
    platform = platforms.Platform(
        platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
    )

    @property
    def reads(self) -> typing.Set[Operand]:
        """Registers and memory references read by this instruction.

        This is a list of string register names and dictionary memory reference
        specifications (i.e., in the form `base + scale * index + offset`).
        """
        r = analyze_bytes(self.instruction, "x86:LE:64:default", self.address)
        return r[0]['use']

    @property
    def writes(self) -> typing.Set[Operand]:
        """Registers and memory references written by this instruction.

        Same format as `reads`.
        """
        r = analyze_bytes(self.instruction, "x86:LE:64:default", self.address)
        return r[0]['def']

