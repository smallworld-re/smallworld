import typing

import capstone

from .bsid import BSIDMemoryReferenceOperand
from .instructions import Instruction, MemoryReferenceOperand, Operand, RegisterOperand


class x86Instruction(Instruction):
    arch = "x86"
    mode = "32"
    angr_arch = "X86"
    cs_arch = capstone.CS_ARCH_X86
    cs_mode = capstone.CS_MODE_32

    def _memory_reference(self, operand) -> MemoryReferenceOperand:
        return BSIDMemoryReferenceOperand(
            base=self._instruction.reg_name(operand.value.mem.base),
            index=self._instruction.reg_name(operand.value.mem.index),
            scale=operand.value.mem.scale,
            offset=operand.value.mem.disp,
            size=operand.size,
        )

    @property
    def reads(self) -> typing.Set[Operand]:
        """Registers and memory references read by this instruction.

        This is a list of string register names and dictionary memory reference
        specifications (i.e., in the form `base + scale * index + offset`).
        """

        reg_reads, _ = self._instruction.regs_access()
        the_reads: typing.Set[Operand] = set(
            [RegisterOperand(self._instruction.reg_name(r)) for r in reg_reads]
        )

        for operand in self._instruction.operands:
            if operand.access & capstone.CS_AC_READ:
                if operand.type == capstone.x86.X86_OP_MEM:
                    if not (self._instruction.mnemonic == "lea"):
                        the_reads.add(self._memory_reference(operand))
                    base_name = self._instruction.reg_name(operand.mem.base)
                    index_name = self._instruction.reg_name(operand.mem.index)
                    if base_name:
                        the_reads.add(RegisterOperand(base_name))
                    if index_name:
                        the_reads.add(RegisterOperand(index_name))
                elif operand.type == capstone.x86.X86_OP_REG:
                    # these are already in the list bc of regs_access above
                    pass
                else:
                    # shouldn't happen
                    assert 1 == 0
        return the_reads

    @property
    def writes(self) -> typing.Set[Operand]:
        """Registers and memory references written by this instruction.

        Same format as `reads`.
        """
        _, reg_writes = self._instruction.regs_access()
        the_writes: typing.Set[Operand] = set(
            [RegisterOperand(self._instruction.reg_name(r)) for r in reg_writes]
        )
        for operand in self._instruction.operands:
            if operand.access & capstone.CS_AC_WRITE:
                # please dont change this to CS_OP_MEM bc that doesnt work?
                if operand.type == capstone.x86.X86_OP_MEM:
                    assert not (self._instruction.mnemonic == "lea")
                    the_writes.add(self._memory_reference(operand))
                elif operand.type == capstone.x86.X86_OP_REG:
                    # operands doesn't contain implicit registers.
                    # we get all registers from regs_write
                    pass
                else:
                    assert 1 == 0
        return the_writes


class AMD64Instruction(x86Instruction):
    mode = "64"
    angr_arch = "AMD64"
    cs_mode = capstone.CS_MODE_64
