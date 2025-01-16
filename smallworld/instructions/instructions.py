import abc
import logging
import typing

import capstone

from .. import emulators, utils

logger = logging.getLogger(__name__)


class Operand(metaclass=abc.ABCMeta):
    """An operand from an instruction."""

    @abc.abstractmethod
    def key(self, emulator: emulators.Emulator):
        """Provide a unique key for this reference.

        Arguments:
            emulator: An emulator from which to fetch a value.

        Returns:
            A key value used to reference this operand.
        """

        pass

    @abc.abstractmethod
    def concretize(
        self, emulator: emulators.Emulator
    ) -> typing.Optional[typing.Union[int, bytes]]:
        """Compute a concrete value for this operand, using an emulator.

        Arguments:
            emulator: An emulator from which to fetch a value.

        Returns:
            The concrete value of this operand.
        """

        pass


class RegisterOperand(Operand):
    """An operand from an instruction that is simply a register."""

    def __init__(self, name: str):
        self.name = name

    def key(self, emulator: emulators.Emulator):
        return self.name

    def __eq__(self, other) -> bool:
        return hash(self) == hash(other)

    def __hash__(self) -> int:
        return hash(self.__repr__())

    def concretize(self, emulator: emulators.Emulator) -> int:
        return emulator.read_register(self.name)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.name})"


class MemoryReferenceOperand(Operand):
    """An operand from an instruction which reads or writes memory."""

    def __init__(self, size: int = 4):
        self.size = size

    @abc.abstractmethod
    def address(self, emulator: emulators.Emulator) -> int:
        """Compute a concrete value for this operand.

        Arguments:
            emulator: An emulator from which to fetch a value.

        Returns:
            The concrete value of this operand.
        """

    def key(self, emulator: emulators.Emulator) -> int:
        return self.address(emulator)

    def __eq__(self, other):
        return self.__repr__() == other.__repr__()

    def __hash__(self):
        return hash(self.__repr__())

    def concretize(self, emulator: emulators.Emulator) -> typing.Optional[bytes]:
        return emulator.read_memory(self.address(emulator), self.size)


class Instruction(metaclass=abc.ABCMeta):
    """An instruction storage and semantic metadata class."""

    def __init__(
        self,
        instruction: bytes,
        address: int,
        _instruction: typing.Optional[capstone.CsInsn] = None,
    ):
        self.instruction = instruction
        self.address = address

        if _instruction is None:
            md = capstone.Cs(self.cs_arch, self.cs_mode)
            md.detail = True

            _instruction = md.disasm(instruction, address).__next__()

        self._instruction = _instruction
        self.disasm = f"{self._instruction.address:x} {self._instruction.mnemonic} {self._instruction.op_str}"

    @property
    @abc.abstractmethod
    def angr_arch(self) -> str:
        """angr architecture ID"""
        return ""

    @property
    @abc.abstractmethod
    def cs_arch(self) -> int:
        """Capstone architecture ID"""
        return 0

    @property
    @abc.abstractmethod
    def cs_mode(self) -> int:
        """Capstone mode ID"""
        return 0

    @classmethod
    def from_capstone(cls, instruction: capstone.CsInsn):
        """Construct from an existing Capstone instruction.

        Arguments:
            instruction: An existing Capstone instruction.
        """
        try:
            return utils.find_subclass(
                cls,
                check=lambda x: x.cs_arch == instruction._cs.arch
                and x.cs_mode == instruction._cs.mode,
                instruction=instruction.bytes,
                address=instruction.address,
                _instruction=instruction,
            )
        except ValueError:
            raise ValueError(
                f"No instruction format for {instruction._cs.arch}:{instruction._cs.mode}"
            )

    @classmethod
    def from_angr(cls, instruction, block, arch: str):
        """Construct from an angr disassembler instruction.

        Arguments:
            instruction: An existing angr disassembler instruction
            arch: angr architecture string
        """
        # angr's instructions don't include raw bytes.
        off = instruction.address - block.addr
        raw = block.bytes[off : off + instruction.size]
        try:
            return utils.find_subclass(
                cls,
                check=lambda x: x.angr_arch == arch,
                instruction=raw,
                address=instruction.address,
            )
        except ValueError:
            raise ValueError(f"No instruction format for {arch}")

    @classmethod
    def from_bytes(cls, raw: bytes, address: int, arch: str, mode: str):
        """Construct from a byte string."""
        try:
            return utils.find_subclass(
                cls,
                check=lambda x: x.arch == arch and x.mode == mode,
                instruction=raw,
                address=address,
            )
        except ValueError:
            raise ValueError(f"No instruction format for {arch}:{mode}")

    @abc.abstractmethod
    def _memory_reference(self, operand) -> MemoryReferenceOperand:
        pass

    @property
    def reads(self) -> typing.Set[Operand]:
        """Registers and memory references read by this instruction.

        This is a list of string register names and dictionary memory reference
        specifications (i.e., in the form `base + scale * index + offset`).
        """

        read: typing.Set[Operand] = set()

        for operand in self._instruction.operands:
            if operand.type == capstone.CS_OP_MEM and (
                not hasattr(operand, "access") or operand.access & capstone.CS_AC_READ
            ):
                read.add(self._memory_reference(operand))
            elif operand.type == capstone.CS_OP_REG and (
                not hasattr(operand, "access") or operand.access & capstone.CS_AC_READ
            ):
                read.add(RegisterOperand(self._instruction.reg_name(operand.reg)))

        return read

    @property
    def writes(self) -> typing.Set[Operand]:
        """Registers and memory references written by this instruction.

        Same format as `reads`.
        """

        write: typing.Set[Operand] = set()

        for operand in self._instruction.operands:
            if operand.type == capstone.CS_OP_MEM and (
                not hasattr(operand, "access") or operand.access & capstone.CS_AC_WRITE
            ):
                write.add(self._memory_reference(operand))
            elif operand.type == capstone.CS_OP_REG and (
                not hasattr(operand, "access") or operand.access & capstone.CS_AC_WRITE
            ):
                write.add(RegisterOperand(self._instruction.reg_name(operand.reg)))

        return write

    # def to_json(self) -> dict:
    #     return {
    #         "instruction": base64.b64encode(self.instruction).decode(),
    #         "disasm": self.disasm,
    #         "address": self.address,
    #         "arch": self.arch,
    #         "mode": self.mode,
    #     }

    # @classmethod
    # def from_json(cls, dict):
    #     if "instruction" not in dict:
    #         raise ValueError(f"malformed {cls.__name__}: {dict!r}")

    #     dict["instruction"] = base64.b64decode(dict["instruction"])

    #     return cls(**dict)

    def __repr__(self) -> str:
        string = f"{self._instruction.mnemonic} {self._instruction.op_str}".strip()

        return f"{self.__class__.__name__}(0x{self.address:x}: {string})"
