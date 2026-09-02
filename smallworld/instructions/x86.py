import typing

import capstone

from smallworld import platforms

from .bsid import x86BSIDMemoryReferenceOperand
from .instructions import Instruction, MemoryReferenceOperand, Operand, RegisterOperand


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

    def _capstone_use_def(self, kind: str) -> typing.Set[Operand]:
        """Capstone use/def for x86, used when the pcode backend is
        unavailable or disabled.

        Overrides the base implementation because x86's
        _memory_reference does not take a single Capstone operand, and
        because implicit registers (flags, the stack pointer for
        push/pop, rax:rdx for mul/div) are only visible through
        regs_access(), not the explicit operand list.
        """
        is_read = kind == "use"
        access = capstone.CS_AC_READ if is_read else capstone.CS_AC_WRITE
        reg_reads, reg_writes = self._instruction.regs_access()
        regs = reg_reads if is_read else reg_writes
        operands: typing.Set[Operand] = {
            RegisterOperand(self._instruction.reg_name(r)) for r in regs
        }
        for operand in self._instruction.operands:
            if not (operand.access & access):
                continue
            if operand.type == capstone.x86.X86_OP_MEM:
                # lea computes an address but accesses no memory, on
                # either side -- so this is unconditional, not gated on
                # is_read: a Capstone build marking lea's operand
                # CS_AC_WRITE would otherwise report a memory def.
                if self._instruction.mnemonic != "lea":
                    operands.add(self._memory_reference_operand(operand))
                if is_read:
                    # the base/index registers are read to form the address
                    for name in (
                        self._instruction.reg_name(operand.mem.base),
                        self._instruction.reg_name(operand.mem.index),
                    ):
                        if name:
                            operands.add(RegisterOperand(name))
            # register operands already came from regs_access above;
            # immediates reference no location.
        if is_read and self._instruction.mnemonic == "pop":
            operands.add(
                self._memory_reference(None, self.sp, None, 1, 0, self.word_size)
            )
        if (not is_read) and self._instruction.mnemonic == "push":
            operands.add(
                self._memory_reference(None, self.sp, None, 1, 0, self.word_size)
            )
        return operands


class AMD64Instruction(x86Instruction):
    angr_arch = "AMD64"
    cs_mode = capstone.CS_MODE_64
    sp = "rsp"
    word_size = 8
    platform = platforms.Platform(
        platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
    )
