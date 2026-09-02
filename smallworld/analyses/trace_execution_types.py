import json
import typing
from dataclasses import dataclass, field
from enum import Enum

from smallworld.instructions import BSIDMemoryReferenceOperand, RegisterOperand

CmpInfo = typing.Union[RegisterOperand, BSIDMemoryReferenceOperand, int]


@dataclass(frozen=True)
class CmpEntry:
    """One thing a comparison compares, with its observed value.

    `source` is a register or memory Operand for a location, or the int
    itself for an immediate. `value` is the concrete value read from the
    live emulator at the moment the compare was about to execute -- an
    immediate maps to itself; None means the location could not be read.

    Self-contained on purpose: the previous contract returned parallel
    lists ("cmp_values is index-aligned with cmp_info"), pushing the
    bookkeeping onto every consumer. The entries carry no lhs/rhs order
    -- they come from the use/def read SET, deduplicated (test al, al
    reports al once) and repr-sorted for run-to-run stability -- so no
    order is promised.
    """

    source: CmpInfo
    value: typing.Optional[int]


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
    cmp: typing.List[CmpInfo]
    branch: bool
    immediates: typing.List[int]
    # Concrete value of each entry in `cmp`, read from the live emulator at the
    # moment this compare is about to execute (see get_cmp_info).  Index-aligned
    # with `cmp`: an immediate maps to itself, a register/memory operand to its
    # concrete integer value, or None if it could not be read.  Excluded from
    # eq/repr so it does not affect trace identity, comparison, or logging/golden
    # output, and so older pickled traces (which lack it) stay compatible.
    cmp_values: typing.List[typing.Optional[int]] = field(
        default_factory=list, compare=False, repr=False
    )

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
