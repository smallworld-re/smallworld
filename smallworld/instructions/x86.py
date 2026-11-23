import typing

import capstone
import claripy

from smallworld import emulators, platforms

from .bsid import BSIDMemoryReferenceOperand, x86BSIDMemoryReferenceOperand
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
            # push PRE-decrements the stack pointer and writes to
            # [sp - word_size], not [sp].
            operands.add(
                self._memory_reference(
                    None, self.sp, None, 1, -self.word_size, self.word_size
                )
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


class x86RealModeMemoryReferenceOperand(BSIDMemoryReferenceOperand):
    """A memory operand in x86 real mode: an offset into a segment.

    The linear address is the segment register's value times 16, plus the
    offset. A 16-bit offset wraps within its 64 KiB segment; a 32-bit one,
    from the address-size prefix, does not. Without a segment override the
    segment is ss for an address based on bp or sp, and ds otherwise.
    """

    _WIDE_REGISTERS = frozenset(
        ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    )
    _STACK_REGISTERS = frozenset(("bp", "sp", "ebp", "esp"))

    def _segment_register(self) -> str:
        if self.segment:
            return self.segment
        return "ss" if self.base in self._STACK_REGISTERS else "ds"

    def _offset_bits(self) -> int:
        if self.base in self._WIDE_REGISTERS or self.index in self._WIDE_REGISTERS:
            return 32
        return 16

    def address(self, emulator: emulators.Emulator) -> int:
        offset = self.offset
        if self.base is not None:
            offset += emulator.read_register(self.base)
        if self.index is not None:
            offset += self.scale * emulator.read_register(self.index)
        offset &= (1 << self._offset_bits()) - 1
        return (emulator.read_register(self._segment_register()) << 4) + offset

    def symbolic_address(self, emulator: emulators.Emulator) -> claripy.ast.bv.BV:
        bits = self._offset_bits()

        def read(name: str) -> claripy.ast.bv.BV:
            value = emulator.read_register_symbolic(name)
            if value.size() < bits:
                value = value.zero_extend(bits - value.size())
            return value[bits - 1 : 0]

        offset = claripy.BVV(self.offset, bits)
        if self.base is not None:
            offset = offset + read(self.base)
        if self.index is not None:
            offset = offset + claripy.BVV(self.scale, bits) * read(self.index)
        segment = emulator.read_register_symbolic(self._segment_register())
        return (segment.zero_extend(16) << 4) + offset.zero_extend(32 - bits)


class x86RealModeInstruction(x86Instruction):
    """An instruction in x86 real mode.

    Its memory operands are offsets into a segment; see
    `x86RealModeMemoryReferenceOperand`.
    """

    angr_arch = "x86:LE:16:Real Mode"
    cs_mode = capstone.CS_MODE_16
    sp = "sp"
    word_size = 2
    platform = platforms.Platform(
        platforms.Architecture.X86_16, platforms.Byteorder.LITTLE
    )

    # Real-mode sleigh forms every segmented address with its `segment`
    # user op, which the p-code analysis cannot see through, so it reports
    # nothing for such an instruction; Capstone reports the operands.
    supports_pcode_use_def = False

    def _memory_reference(self, segment, base, index, scale, offset, size):
        return x86RealModeMemoryReferenceOperand(
            segment=segment,
            base=base,
            index=index,
            scale=scale,
            offset=offset,
            size=size,
        )
