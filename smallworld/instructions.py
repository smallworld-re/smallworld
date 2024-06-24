import abc
import base64
import logging
import typing

import capstone

from . import emulators, utils

logger = logging.getLogger(__name__)


class Operand(metaclass=abc.ABCMeta):
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
        """Compute a concrete value for this operand.

        Arguments:
            emulator: An emulator from which to fetch a value.

        Returns:
            The concrete value of this operand.
        """

        pass


class RegisterOperand(Operand):
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


class x86MemoryReferenceOperand(MemoryReferenceOperand, utils.Serializable):
    def __init__(
        self,
        base: typing.Optional[str] = None,
        index: typing.Optional[str] = None,
        scale: int = 1,
        offset: int = 0,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)

        self.base = base
        self.index = index
        self.scale = scale
        self.offset = offset

    def address(self, emulator: emulators.Emulator) -> int:
        base = 0
        if self.base is not None:
            base = emulator.read_register(self.base)

        index = 0
        if self.index is not None:
            index = emulator.read_register(self.index)

        return base + self.scale * index + self.offset

    def to_json(self) -> dict:
        return {
            "base": self.base,
            "index": self.index,
            "scale": self.scale,
            "offset": self.offset,
        }

    @classmethod
    def from_json(cls, dict):
        if any(k not in dict for k in ("base", "index", "scale", "offset")):
            raise ValueError(f"malformed {cls.__name__}: {dict!r}")

        return cls(**dict)

    def __repr__(self) -> str:
        string = ""

        if self.base:
            string = f"{self.base}"

        if self.index:
            if self.scale:
                string = f"{string}+{self.scale}*{self.index}"
            else:
                string = f"{string}+{self.index}"

        if self.offset:
            string = f"{string}+{self.offset}"

        return f"{self.__class__.__name__}({string})"


class Instruction(utils.Serializable):
    """An instruction storage and semantic metadata class.

    Arguments:
        instruction: The raw bytes of an instruction.
        address: The address at which this instruction appeared.
        arch: An architecture string.
        mode: A mode string.
    """

    ARCH_X86 = "x86"
    """x86 architecture."""

    ARCH_ARM = "arm"
    """arm32 architecture."""

    ARCH_SPARC = "sparc"
    """SPARC architecture."""

    MODE_ARM = "arm"
    MODE_THUMB = "thumb"

    MODE_32 = "32"
    """32-bit mode."""
    MODE_64 = "64"
    """64-bit mode."""
    MODE_V8 = "v8"
    """sparc v8 mode, aka 32-bit"""
    MODE_V9 = "v9"
    """Sparc v9 mode, aka 64-bit"""

    CAPSTONE_ARCH_MAP = {
        ARCH_X86: capstone.CS_ARCH_X86,
        ARCH_ARM: capstone.CS_ARCH_ARM,
        ARCH_SPARC: capstone.CS_ARCH_SPARC,
    }
    CAPSTONE_REVERSE_ARCH_MAP = {v: k for k, v in CAPSTONE_ARCH_MAP.items()}

    CAPSTONE_MODE_MAP = {
        MODE_32: capstone.CS_MODE_32,
        MODE_64: capstone.CS_MODE_64,
        MODE_ARM: capstone.CS_MODE_ARM,
        MODE_THUMB: capstone.CS_MODE_THUMB,
        MODE_V8: capstone.CS_MODE_V8,
        MODE_V9: capstone.CS_MODE_V9,
    }
    CAPSTONE_REVERSE_MODE_MAP = {v: k for k, v in CAPSTONE_MODE_MAP.items()}

    # angr doesn't maintain a separate notion of mode;
    # both are encoded in the architecture ID.
    # It also has more than one architecture ID scheme,
    ANGR_ARCH_MODE_MAP = {
        "AMD64": (ARCH_X86, MODE_64),
        "sparc:BE:32:default": (ARCH_SPARC, MODE_V8),
        "sparc:BE:64:default": (ARCH_SPARC, MODE_V9),
    }

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
        self.disasm = f"{self._instruction.address:x} {self._instruction.mnemonic} {self._instruction.op_str}"

    @classmethod
    def from_capstone(cls, instruction: capstone.CsInsn):
        """Construct from an existing Capstone instruction.

        Arguments:
            instruction: An existing Capstone instruction.
        """

        if instruction._cs.arch == capstone.CS_ARCH_X86:
            return x86Instruction(
                instruction=instruction.bytes,
                address=instruction.address,
                arch=cls.CAPSTONE_REVERSE_ARCH_MAP[instruction._cs.arch],
                mode=cls.CAPSTONE_REVERSE_MODE_MAP[instruction._cs.mode],
                _instruction=instruction,
            )
        else:
            return cls(
                instruction=instruction.bytes,
                address=instruction.address,
                arch=cls.CAPSTONE_REVERSE_ARCH_MAP[instruction._cs.arch],
                mode=cls.CAPSTONE_REVERSE_MODE_MAP[instruction._cs.mode],
                _instruction=instruction,
            )

    @classmethod
    def from_angr(cls, instruction, block, arch: str):
        """Construct from an angr disassembler instruction

        Arguments:
            instruction: An existing angr disassembler instruction
            arch: angr architecture string
        """
        (arch, mode) = cls.ANGR_ARCH_MODE_MAP[arch]
        # angr's instructions don't include raw bytes.
        off = instruction.address - block.addr
        raw = block.bytes[off : off + instruction.size]
        return cls(instruction=raw, address=instruction.address, arch=arch, mode=mode)

    @classmethod
    def from_bytes(cls, *args, **kwargs):
        """Construct from a byte string."""

        return cls(*args, **kwargs)

    def _memory_reference(self, operand) -> MemoryReferenceOperand:
        return x86MemoryReferenceOperand(
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

        registers, _ = self._instruction.regs_access()

        read: typing.Set[Operand] = set(
            [RegisterOperand(self._instruction.reg_name(r)) for r in registers]
        )

        for operand in self._instruction.operands:
            if (
                operand.type == capstone.CS_OP_MEM
                and operand.access & capstone.CS_AC_READ
            ):
                read.add(self._memory_reference(operand))

        return read

    @property
    def writes(self) -> typing.Set[Operand]:
        """Registers and memory references written by this instruction.

        Same format as `reads`.
        """

        _, registers = self._instruction.regs_access()

        write: typing.Set[Operand] = set(
            [RegisterOperand(self._instruction.reg_name(r)) for r in registers]
        )

        for operand in self._instruction.operands:
            if (
                operand.type == capstone.CS_OP_MEM
                and operand.access & capstone.CS_AC_WRITE
            ):
                write.add(self._memory_reference(operand))

        return write

    def to_json(self) -> dict:
        return {
            "instruction": base64.b64encode(self.instruction).decode(),
            "disasm": self.disasm,
            "address": self.address,
            "arch": self.arch,
            "mode": self.mode,
        }

    @classmethod
    def from_json(cls, dict):
        if "instruction" not in dict:
            raise ValueError(f"malformed {cls.__name__}: {dict!r}")

        dict["instruction"] = base64.b64decode(dict["instruction"])

        return cls(**dict)

    def __repr__(self) -> str:
        string = f"{self._instruction.mnemonic} {self._instruction.op_str}".strip()

        return f"{self.__class__.__name__}(0x{self.address:x}: {string}; {self.arch}, {self.mode})"


class x86Instruction(Instruction):
    @property
    def reads(self) -> typing.Set[Operand]:
        """Registers and memory references read by this instruction.

        This is a list of string register names and dictionary memory reference
        specifications (i.e., in the form `base + scale * index + offset`).
        """

        the_reads: typing.Set[Operand] = set([])
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
                    the_reads.add(
                        RegisterOperand(self._instruction.reg_name(operand.reg))
                    )
                else:
                    assert 1 == 0
        return the_reads

    @property
    def writes(self) -> typing.Set[Operand]:
        """Registers and memory references written by this instruction.

        Same format as `reads`.
        """

        the_writes: typing.Set[Operand] = set([])
        for operand in self._instruction.operands:
            if operand.access & capstone.CS_AC_WRITE:
                # please dont change this to CS_OP_MEM bc that doesnt work?
                if operand.type == capstone.x86.X86_OP_MEM:
                    assert not (self._instruction.mnemonic == "lea")
                    the_writes.add(self._memory_reference(operand))
                elif operand.type == capstone.x86.X86_OP_REG:
                    the_writes.add(
                        RegisterOperand(self._instruction.reg_name(operand.reg))
                    )
                else:
                    assert 1 == 0

        return the_writes
