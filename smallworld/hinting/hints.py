import typing
from dataclasses import dataclass

import networkx as nx

from .. import hinting


@dataclass(frozen=True)
class PointerHint(hinting.Hint):
    """We found a pointer

    Arguments:
        instruction: The instruction containing the pointer.
        pointer: The pointer.
    """

    instruction: typing.Any
    pointer: typing.Any


@dataclass(frozen=True)
class ControlFlowHint(hinting.Hint):
    """Represents control flow going from the from_instruction to the to_instruction.

    Arguments:
        from_instruction: The from instruction
        to_instruction: The to instruction
    """

    from_instruction: typing.Any
    to_instruction: typing.Any


@dataclass(frozen=True)
class CoverageHint(hinting.Hint):
    """Holds the a map of program counter to hit counter for an execution.

    Arguments:
        coverage: A map from program counter to hit count
    """

    coverage: typing.Dict[int, int]


@dataclass(frozen=True)
class ReachableCodeHint(hinting.Hint):
    """Indicates that we can get to a given program counter with symbolic execution.

    Arguments:
        address: The address we can reach
    """

    address: int


@dataclass(frozen=True)
class EmulationException(hinting.Hint):
    """Something went wrong emulating this instruction"""

    # instruction: typing.Any
    pc: int
    instruction_num: int
    exception: str


@dataclass(frozen=True)
class UnderSpecifiedValueHint(hinting.Hint):
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
class UntypedUnderSpecifiedRegisterHint(UnderSpecifiedRegisterHint):
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
class TypeHint(hinting.Hint):
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
class OutputHint(hinting.Hint):
    registers: typing.Dict[str, str]
    memory: typing.Dict[int, str]


# These next three are used by the colorizer


@dataclass(frozen=True)
class MemoryUnavailableHint(hinting.Hint):
    """Represents a load or store that was unavailable memory.

    Arguments:
      is_read: true if a load else a store
      size: size of read/write in bytes
      base_reg_name: name of base register (if known)
      base_reg_val: value of base register (if known)
      index_reg_name: name of index register (if known)
      index_reg_val: value of index register (if known)
      offset: offset (if known, else 0)
      scale: scale (if known, else 0)
      address: memory address of this value
      instruction: a smallworld instruction
      pc: program counter of that instruction
      micro_exec_num: micro-execution run number
      instruction_num: for micro-execution the instr count
    """

    is_read: bool
    size: int
    base_reg_name: str
    base_reg_val: int
    index_reg_name: str
    index_reg_val: int
    offset: int
    scale: int
    address: int
    pc: int
    micro_exec_num: int
    instruction_num: int


@dataclass(frozen=True)
class MemoryUnavailableSummaryHint(hinting.Hint):
    is_read: bool
    size: int
    base_reg_name: str
    index_reg_name: str
    offset: int
    scale: int
    pc: int
    count: int
    num_micro_executions: int


@dataclass(frozen=True)
class DynamicValueHint(hinting.Hint):
    """Represents a concrete value either in a register or memory
    encountered during emulation-base analysis

    Arguments:
      instruction: a smallworld instruction
      pc: program counter of that instruction
      micro_exec_num: micro-execution run number
      instruction_num: for micro-execution the instr count
      dynamic_value: this is the actual value
      size: the size of the value in bytes
      use: True if its a "use" of this value, else its a "def"
      new: True if its a new value, first sighting
    """

    # instruction: typing.Any
    pc: int
    micro_exec_num: int
    instruction_num: int
    dynamic_value: int
    color: int
    size: int
    use: bool
    new: bool


@dataclass(frozen=True)
class DynamicRegisterValueHint(DynamicValueHint):
    """Represents a concrete register value encountered during
    analysis, either used or defined by some instruction.

    Arguments:
      reg_name: name of the register
      dynamic_value: this is the actual value as bytes
      use: True if its a "use" of this value, else its a "def"
      capstone_instruction: the instruction in capstone parlance
      pc: program counter of that instruction
      micro_exec_num: micro-execution run number
      instruction_num: for micro-execution the instr count
      info: extra info about use or def if available
    """

    reg_name: str


@dataclass(frozen=True)
class DynamicMemoryValueHint(DynamicValueHint):
    """Represents a concrete memory value encountered during
    analysis, either used or defined by some instruction.

    Arguments:
      address: memory address of this value
      base: base address (if known, else 0)
      index: index (if known, else 0)
      scale: scale (if known, else 0)
      offset: offset (if known, else 0)
      dynamic_value: this is the actual value as bytes
      use: True if its a "use" of this value, else its a "def"
      capstone_instruction: the instruction in capstone parlance
      pc: program counter of that instruction
      micro_exec_num: micro-execution run number
      instruction_num: for micro-execution the instr count
      info: extra info about use or def if available
    """

    address: int
    base: str
    index: str
    scale: int
    offset: int


@dataclass(frozen=True)
class DynamicValueSummaryHint(hinting.Hint):
    # instruction: typing.Any
    pc: int
    color: int
    size: int
    use: bool
    new: bool
    count: int
    num_micro_executions: int


@dataclass(frozen=True)
class DynamicMemoryValueSummaryHint(DynamicValueSummaryHint):
    base: str
    index: str
    scale: int
    offset: int


@dataclass(frozen=True)
class DynamicRegisterValueSummaryHint(DynamicValueSummaryHint):
    reg_name: str


@dataclass(frozen=True)
class DefUseGraphHint(hinting.Hint):
    graph: nx.MultiDiGraph


__all__ = [
    "DynamicRegisterValueHint",
    "DynamicMemoryValueHint",
    "MemoryUnavailableHint",
    "DynamicRegisterValueSummaryHint",
    "DynamicMemoryValueSummaryHint",
    "MemoryUnavailableSummaryHint",
    "EmulationException",
    "CoverageHint",
    "ControlFlowHint",
    "ReachableCodeHint",
    "DefUseGraphHint",
]
