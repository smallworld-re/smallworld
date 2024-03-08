import base64
import json
import logging
import sys
import typing
from dataclasses import InitVar, asdict, dataclass, field

# logging re-exports
from logging import WARNING
from typing import List

import capstone as cs


class HintJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Hint):
            d = asdict(o)
            d["hint_type"] = o.__class__.__name__
            return d
        return super().default(o)


class HintJSONDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, dict):
        if "hint_type" in dict:
            cls = getattr(sys.modules[__name__], dict["hint_type"])
            del dict["hint_type"]
            return cls(**dict)
        return dict


@dataclass(frozen=True)
class HintInstruction:
    """We can't put Capstone instructions in hints, so we use these instead."""

    address: int
    instruction: str
    instruction_bytes: bytes
    reads: List[str]
    writes: List[str]


@dataclass(frozen=True)
class Hint:
    """Base class for all Hints.

    Arguments:
        message: A message for this Hint.
    """

    message: str


@dataclass(frozen=True)
class EmulationException(Hint):
    """Something went wrong emulating this instruction"""

    capstone_instruction: InitVar[cs.CsInsn]
    instruction: HintInstruction = field(init=False)
    pc: int
    micro_exec_num: int
    instruction_num: int
    exception: str

    def __post_init__(self, capstone_instruction):
        address = capstone_instruction.address
        instruction_string = (
            f"{capstone_instruction.mnemonic} {capstone_instruction.op_str}"
        )
        instruction_bytes = base64.b64encode(capstone_instruction.bytes).decode()
        (regs_read, regs_written) = capstone_instruction.regs_access()
        reads = []
        for r in regs_read:
            reads.append(f"{capstone_instruction.reg_name(r)}")
        writes = []
        for w in regs_written:
            writes.append(f"{capstone_instruction.reg_name(w)}")
        object.__setattr__(
            self,
            "instruction",
            HintInstruction(
                address=address,
                instruction=instruction_string,
                instruction_bytes=instruction_bytes,
                reads=reads,
                writes=writes,
            ),
        )


@dataclass(frozen=True)
class UnderSpecifiedValueHint(Hint):
    """Super class for UnderSpecified Value Hints"""

    capstone_instruction: InitVar[cs.CsInsn]
    instruction: HintInstruction = field(init=False)
    pc: int

    def __post_init__(self, capstone_instruction):
        address = capstone_instruction.address
        instruction_string = (
            f"{capstone_instruction.mnemonic} {capstone_instruction.op_str}"
        )
        instruction_bytes = base64.b64encode(capstone_instruction.bytes).decode()
        (regs_read, regs_written) = capstone_instruction.regs_access()
        reads = []
        for r in regs_read:
            reads.append(f"{capstone_instruction.reg_name(r)}")
        writes = []
        for w in regs_written:
            writes.append(f"{capstone_instruction.reg_name(w)}")
        object.__setattr__(
            self,
            "instruction",
            HintInstruction(
                address=address,
                instruction=instruction_string,
                instruction_bytes=instruction_bytes,
                reads=reads,
                writes=writes,
            ),
        )


@dataclass(frozen=True)
class UnderSpecifiedRegisterHint(UnderSpecifiedValueHint):
    """Represents a register whose value can't be fully determined from the environment.

    Arguments:
        register: The register in question
    """

    register: str


@dataclass(frozen=True)
class UnderSpecifiedMemoryHint(UnderSpecifiedValueHint):
    """Represents a memory range whose value can't be fully determined from the environment.

    Arguments:
        address: The address of the beginning of the range
        size: The size of the range
    """

    address: int
    size: int


@dataclass(frozen=True)
class UnderSpecifiedMemoryRefHint(UnderSpecifiedValueHint):
    """Represents a memory range whose value can't be fully determined from the environment.

    Arguments:
        address: The address of the beginning of the range
        size: The size of the range
    """

    base: typing.Tuple[str, int]
    index: typing.Tuple[str, int]
    offset: int


@dataclass(frozen=True)
class UnderSpecifiedAddressHint(UnderSpecifiedValueHint):
    """Represents a symbolic address that can't be resolved from the environment.
    Arguments:
        symbol: Name of the symbolic value
        addr:   Address expression containing the symbol
    """

    symbol: str
    addr: str


@dataclass(frozen=True)
class TypedUnderSpecifiedRegisterHint(UnderSpecifiedRegisterHint):
    typedef: str
    value: str


@dataclass(frozen=True)
class UnypedUnderSpecifiedRegisterHint(UnderSpecifiedRegisterHint):
    value: str


@dataclass(frozen=True)
class TypedUnderSpecifiedMemoryHint(UnderSpecifiedMemoryHint):
    typedef: str
    value: str


@dataclass(frozen=True)
class UntypedUnderSpecifiedMemoryHint(UnderSpecifiedMemoryHint):
    value: str


@dataclass(frozen=True)
class TypedUnderSpecifiedAddressHint(UnderSpecifiedAddressHint):
    typedef: str
    value: str


@dataclass(frozen=True)
class UntypedUnderSpecifiedAddressHint(UnderSpecifiedAddressHint):
    value: str


@dataclass(frozen=True)
class InputUseHint(UnderSpecifiedValueHint):
    """Represents an instruction at which some register input value is used,
       i.e. an information flow from input to some instruction

    Arguments:
      input_reg: The name of the register input value (source)
      instr: The instruction in which the input is used
      pc: program counter of that instruction
      use_reg: The name of the register in instr that is using the input value
    """

    input_register: str
    micro_exec_num: int
    instruction_num: int
    use_register: str


@dataclass(frozen=True)
class TypeHint(Hint):
    """Super class for Type Hints"""

    pass


@dataclass(frozen=True)
class RegisterPointerHint(TypeHint):
    """Signal that a register is probably a pointer.

    Arguments:
        register: The register in question
    """

    register: str


@dataclass(frozen=True)
class RegisterPointsToHint(RegisterPointerHint):
    """Signal that a register is probably a pointer and points to a type.

    Arguments:
        type: The type in question
    """

    type: str


@dataclass(frozen=True)
class MemoryPointerHint(TypeHint):
    """Signal that a memory address is probably a pointer.

    Arguments:
       address: The address in question
    """

    address: int


@dataclass(frozen=True)
class MemoryPointsToHint(RegisterPointerHint):
    """Signal that a memory address is probably a pointer and points to a type.

    Arguments:
        type: The type in question
    """

    type: str


@dataclass(frozen=True)
class StructureHint(TypeHint):
    """Signals the probable layout of a struct

    Arguments:
        layout: A dictionary of offset to type
    """

    layout: typing.Dict[int, str]


@dataclass(frozen=True)
class OutputHint(Hint):
    registers: typing.Dict[str, str]
    memory: typing.Dict[int, str]


class HintSubclassFilter(logging.Filter):
    """A custom logging filter based on Hint class."""

    def __init__(self, hint: typing.Type[Hint], *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.hint = hint

    def filter(self, record):
        return isinstance(record.msg, self.hint)


class Hinter(logging.Logger):
    """A custom logger that only accepts Hints."""

    def _log(self, level, msg, *args, **kwargs):
        if not isinstance(msg, Hint):
            raise ValueError(f"{repr(msg)} is not a Hint")

        return super()._log(level, msg, *args, **kwargs)


root = Hinter(name="root", level=WARNING)
Hinter.root = typing.cast(logging.RootLogger, root)
Hinter.manager = logging.Manager(Hinter.root)
Hinter.manager.loggerClass = Hinter


def getHinter(name: typing.Optional[str] = None) -> Hinter:
    """Get a hinter with the given name.

    Arguments:
        name: The name of the hinter to get - if `None` this returns the
            root Hinter.

    Returns:
        A Hinter with the given name.
    """

    if not name or isinstance(name, str) and name == root.name:
        return root

    return typing.cast(Hinter, Hinter.manager.getLogger(name))


__all__ = [
    "Hint",
    "EmulationException",
    "UnderSpecifiedValueHint",
    "UnderSpecifiedRegisterHint",
    "UnderSpecifiedMemoryHint",
    "UnderSpecifiedMemoryRefHint",
    "InputUseHint",
    "TypeHint",
    "RegisterPointerHint",
    "RegisterPointsToHint",
    "MemoryPointerHint",
    "MemoryPointsToHint",
    "StructureHint",
    "getHinter",
]
