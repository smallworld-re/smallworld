import base64
import typing

import capstone

from . import emulators, utils


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

    MODE_32 = "32"
    """32-bit mode."""
    MODE_64 = "64"
    """64-bit mode."""

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
        """Construct from an existing Capstone instruction.

        Arguments:
            instruction: An existing Capstone instruction.
        """

        return cls(
            instruction=instruction.bytes,
            address=instruction.address,
            arch=cls.CAPSTONE_REVERSE_ARCH_MAP[instruction._cs.arch],
            mode=cls.CAPSTONE_REVERSE_MODE_MAP[instruction._cs.mode],
            _instruction=instruction,
        )

    @classmethod
    def from_bytes(cls, *args, **kwargs):
        """Construct from a byte string."""

        return cls(*args, **kwargs)

    Operand = typing.Union[str, typing.Dict[str, typing.Union[str, int]]]

    def _operand(self, operand) -> Operand:
        return {
            "base": self._instruction.reg_name(operand.value.mem.base),
            "index": self._instruction.reg_name(operand.value.mem.index),
            "scale": operand.value.mem.scale,
            "offset": operand.value.mem.disp,
            "size": operand.size,
        }

    @property
    def reads(self) -> typing.List[Operand]:
        """Registers and memory references read by this instruction.

        This is a list of string register names and dictionary memory reference
        specifications (i.e., in the form `base + scale * index + offset`).
        """

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
    def writes(self) -> typing.List[Operand]:
        """Registers and memory references written by this instruction.

        Same format as `reads`.
        """

        _, registers = self._instruction.regs_access()

        write = [self._instruction.reg_name(r) for r in registers]

        for operand in self._instruction.operands:
            if (
                operand.type == capstone.CS_OP_MEM
                and operand.access & capstone.CS_AC_WRITE
            ):
                write.append(self._operand(operand))

        return write

    @classmethod
    def concretize(
        cls, values: typing.List[Operand], emulator: emulators.Emulator
    ) -> typing.Dict[typing.Union[str, int], typing.Union[int, bytes, None]]:
        """Get concrete values for a list of operands.

        Arguments:
            values: A list of instruction operands - like those returned by
                `reads` and `writes`.
            emulator: The emulator from which to read state.

        Returns:
            A `dict` mapping operand specifications to concrete values from the
            given emulator.
        """

        concrete: typing.Dict[
            typing.Union[str, int], typing.Union[int, bytes, None]
        ] = {}
        for value in values:
            if isinstance(value, str):
                concrete[value] = emulator.read_register(value)
            elif isinstance(value, dict):
                if list(value.keys()) < ["base", "index", "scale", "offset", "size"]:
                    raise ValueError(
                        f"malformed memory reference identifier: {value!r}"
                    )

                def read_register(name):
                    if name is not None:
                        if not isinstance(name, str):
                            raise ValueError(
                                "malformed memory reference identifier: {value!r}"
                            )
                        return emulator.read_register(value["base"])
                    return 0

                base = read_register(value["base"])
                index = read_register(value["index"])

                address = base + value["scale"] * index + value["offset"]

                concrete[address] = emulator.read_memory(address, int(value["size"]))
            else:
                raise ValueError(f"unsupported value identifier: {value!r}")

        return concrete

    def to_json(self) -> dict:
        return {
            "instruction": base64.b64encode(self.instruction).decode(),
            "address": self.address,
            "arch": self.arch,
            "mode": self.mode,
        }

    @classmethod
    def from_json(cls, dict):
        if "instruction" not in dict:
            raise ValueError(f"malformed {cls.__name__}: {dict!r}")

        dict["instruction"] = base64.b64decode(dict["instruction"])

        cls(**dict)

    def __repr__(self) -> str:
        string = f"{self._instruction.mnemonic} {self._instruction.op_str}".strip()

        return f"{self.__class__.__name__}(0x{self.address:x}: {string}; {self.arch}, {self.mode})"
