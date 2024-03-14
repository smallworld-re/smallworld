import logging
import typing
from dataclasses import dataclass

# logging re-exports
from logging import WARNING

from . import utils


@dataclass(frozen=True)
class Hint(utils.Serializable):
    """Base class for all Hints.

    Arguments:
        message: A message for this Hint.
    """

    message: str

    def to_json(self) -> dict:
        return self.__dict__

    @classmethod
    def from_json(cls, dict):
        return cls(**dict)


@dataclass(frozen=True)
class EmulationException(Hint):
    """Something went wrong emulating this instruction"""

    instruction: typing.Any
    micro_exec_num: int
    instruction_num: int
    exception: str


@dataclass(frozen=True)
class UnderSpecifiedValueHint(Hint):
    """Super class for UnderSpecified Value Hints"""

    instruction: typing.Any


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
class UnderSpecifiedBranchHint(UnderSpecifiedValueHint):
    """Represents a program fork based on an under-specified condition."""


@dataclass(frozen=True)
class UnderSpecifiedMemoryBranchHint(UnderSpecifiedBranchHint):
    """Represents conditional data flow with an under-specified conditional

    Arguments:
      addr: Offending address expression
      options: Possible evaluations of addr, paired with their guard expressions.
    """

    address: str
    options: typing.List[typing.Tuple[str, str]]


@dataclass(frozen=True)
class UnderSpecifiedControlBranchHint(UnderSpecifiedBranchHint):
    """Represents conditional control flow with an under-specified conditional

    Arguments:
      targets: Possible branch target addresses, paired with guard expressions.
    """

    targets: typing.Dict[str, str]


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
