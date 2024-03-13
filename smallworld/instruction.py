import typing

import capstone


class Instruction:
    ARCH_X86 = "x86"

    MODE_32 = "32"
    MODE_64 = "64"

    CAPSTONE_ARCH_MAP = {ARCH_X86: capstone.CS_ARCH_X86}
    CAPSTONE_REVERSE_ARCH_MAP = {v: k for k, v in CAPSTONE_ARCH_MAP.items()}

    CAPSTONE_MODE_MAP = {MODE_32: capstone.CS_MODE_32, MODE_64: capstone.CS_MODE_64}
    CAPSTONE_REVERSE_MODE_MAP = {v: k for k, v in CAPSTONE_MODE_MAP.items()}

    def __init__(
        self,
        instruction: bytes,
        address: int,
        arch: str,
        mode: str,
        _instruction: typing.Optional[capstone.CsInsn] = None,
    ):
        self.instruction = instruction
        self.address = address
        self.arch = arch
        self.mode = mode

        if _instruction is None:
            md = capstone.Cs(self.CAPSTONE_ARCH_MAP[arch], self.CAPSTONE_MODE_MAP[mode])
            md.detail = True

            _instruction = md.disasm(instruction, address).__next__()

        self._instruction = _instruction

    @classmethod
    def from_capstone(cls, instruction: capstone.CsInsn):
        return cls(
            instruction=instruction.bytes,
            address=instruction.address,
            arch=cls.CAPSTONE_REVERSE_ARCH_MAP[instruction._cs.arch],
            mode=cls.CAPSTONE_REVERSE_MODE_MAP[instruction._cs.mode],
            _instruction=instruction,
        )

    @classmethod
    def from_bytes(cls, *args, **kwargs):
        return cls(*args, **kwargs)

    def _operand(self, operand):
        return {
            "base": self._instruction.reg_name(operand.value.mem.base),
            "index": self._instruction.reg_name(operand.value.mem.index),
            "scale": operand.value.mem.scale,
            "offset": operand.value.mem.disp,
            "size": operand.size,
        }

    @property
    def reads(self) -> typing.List[str]:
        registers, _ = self._instruction.regs_access()
        read = [self._instruction.reg_name(r) for r in registers]

        for operand in self._instruction.operands:
            if (
                operand.type == capstone.CS_OP_MEM
                and operand.access & capstone.CS_AC_READ
            ):
                read.append(self._operand(operand))

        return read

    @property
    def writes(self) -> typing.List[str]:
        _, registers = self._instruction.regs_access()

        write = [self._instruction.reg_name(r) for r in registers]

        for operand in self._instruction.operands:
            if (
                operand.type == capstone.CS_OP_MEM
                and operand.access & capstone.CS_AC_WRITE
            ):
                write.append(self._operand(operand))

        return write

    def __repr__(self) -> str:
        string = f"{self._instruction.mnemonic} {self._instruction.op_str}".strip()

        return f"{self.__class__.__name__}(0x{self.address:x}: {string}; {self.arch}, {self.mode})"
