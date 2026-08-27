import json
import typing
from dataclasses import dataclass, field
from enum import Enum

from smallworld.instructions import BSIDMemoryReferenceOperand, RegisterOperand

#: Kept as an alias for CmpEntry.source's type; magrathea imports it.
CmpInfo = typing.Union[RegisterOperand, BSIDMemoryReferenceOperand]


@dataclass(frozen=True)
class CmpEntry:
    """One LOCATION a comparison compares -- a register or memory operand
    -- with the value observed there at that point in the trace.

    Immediates are not entries: they live in the separate immediates list
    (a constant is not a location, and needs no observation).

    `value` is excluded from equality and repr on purpose: trace identity
    and golden logging must not depend on the seeded runtime values, the
    same rule TraceElement.cmp_values carried before this type subsumed
    it. None means the location could not be read.
    """

    source: CmpInfo
    value: typing.Optional[int] = field(default=None, compare=False, repr=False)


class TraceRes(Enum):
    ER_NONE = 0
    ER_BOUNDS = 1
    ER_MAX_INSNS = 2
    ER_FAIL = 3
    # Reached a designated exit point (e.g. the harnessed function's ret) -- a
    # clean, intended completion. Distinct from ER_BOUNDS, which is execution
    # escaping the allowed region (e.g. an indirect jump through a garbage
    # pointer). Both were formerly collapsed into ER_BOUNDS.
    ER_EXITPOINT = 4


# one element in a trace
@dataclass
class TraceElement:
    pc: int
    ic: int  # instruction count
    mnemonic: str
    op_str: str
    # The locations this instruction compares (CmpEntry: operand + observed
    # value) and, separately, the immediates it compares against. NOTE: this
    # shape is a deliberate break from the older mixed cmp list plus
    # index-aligned cmp_values; old pickled traces do not load.
    cmp: typing.List[CmpEntry]
    branch: bool
    immediates: typing.List[int]

    def __str__(self):
        return f"{self.ic} 0x{self.pc:x} [{self.mnemonic} {self.op_str}] {self.cmp} {self.branch} {self.immediates}"

    # NOTE this is just used for logging. Can't un-jsonify
    def to_json(self):
        d = {
            "instruction_count": self.ic,
            "pc": self.pc,
            "instr": f"{self.mnemonic} {self.op_str}",
            "cmp": str(self.cmp),
            "branch": self.branch,
            "immediates": self.immediates,
        }
        return json.dumps(d)
