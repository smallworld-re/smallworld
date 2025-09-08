import typing
from dataclasses import dataclass
from enum import Enum
import json

from smallworld.instructions import Operand

CmpInfo = typing.Tuple[str, Operand, int]


class TraceRes(Enum):
    ER_NONE = 0
    ER_BOUNDS = 1
    ER_MAX_INSNS = 2
    ER_FAIL = 3


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
            "immediates": self.immediates
        }
        return json.dumps(d)
