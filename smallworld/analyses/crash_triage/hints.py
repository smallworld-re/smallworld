import enum
import typing
from dataclasses import dataclass

from ... import hinting

# Crash triage results have two major pieces,
# the initial Triage failure, and the angr analysis results
#
# Triage result can be one of the following:
#
# 1. No failure detected
#   a. Means that the program exited via an exit point.
#   b. No further analysis performed; this isn't a crash.
# 2. Out of Bounds (OOB) execution
# 3. Illegal
# 4. Trap
#   a. Giving any details about why this happened is an abject pain.
# 5. Memory fault
#
# All Triage failures include an instruction trace.
# Memory faults may include a set of potentially-responsible instruction operands.
#
# Angr analysis can end in one of the following states:
#
# 1. Did not reach the failure
#   a. Divergence from the Triage trace
#   b. Early termination due to emulation halt
#   c. Early termination due to unexecutable instruction
# 2. OOB
#   a. Failed to reproduce the failure
#   b. Emulation halt at expected instruction
# 3. Illegal
#   a. Angr lifter agrees that instruction is unexecutable
#   b. Angr lifter does not agree that the instruction is unexecutable
# 4. Trap
#   a. angr reached the target instruction successfully.
# 5. Memory
#   a. Dereference of an uninitializd pointer
#   b. Dereference of a pointer outside
#
# A few steps need further explanation
#
# 1. Execution Halt:
#   a. Unconstrained instruction pointer
#       i. Return address was unconstrained
#       ii. Call target was unconstrained
#       iii. Ordinary jump target was unconstrained
#   a. Path deadended
#       i. Next PC is an exit point; this exited normally.
#       i. Next PC is out of bounds
#       ii. Next PC is in unmapped memory
#       iii. No clear cause for the deadending.
#   b. Path diverged
#       i. Due to how most ISAs work, this nearly only ever happens as an early termination.
#
# 2. Unexecutable Instruction:
#   a. Pyvex decodes the instruction, and it's actually decodable.
#   b. Pyvex pretends to decode the instruction; it's actually not decodable.
#       i. Example: amd64 ud2
#   c. Pyvex does not represent the instruction, it's actually decodable
#       i. Example: arm VFP
#   d. Pyvex does not decode the instruction because it's actually not decodable.
#
# 3. Uninitialized Pointer:
#   a.


# ****************************************************
# *** Helper: Describe an unconstrained expression ***
# ****************************************************
@dataclass
class Expression:
    expr: str
    usr_labels: typing.Set[str]
    init_reg_labels: typing.Set[str]
    init_mem_labels: typing.Set[str]
    unk_reg_labels: typing.Set[str]
    unk_mem_labels: typing.Set[str]
    unk_unk_labels: typing.Set[str]


# *******************************************
# *** Helper: Describe an unexpected halt ***
# *******************************************
@dataclass(frozen=True)
class Halt:
    pass


@dataclass(frozen=True)
class HaltNoHalt(Halt):
    """Program would not actually halt here.

    Attributes:
        pc: Next program counter
    """

    pc: int


@dataclass(frozen=True)
class HaltUnconstrained(Halt):
    """Program halted because of an unconstrained program counter

    Attributes:
        kind: String describing the kind of jump involved
        expr: Description of the program counter expression
    """

    kind: str
    expr: Expression


@dataclass(frozen=True)
class HaltDeadended(Halt):
    """Program halted because it left program bounds

    Attributes:
        kind: String describing the reason the program likely halted
        pc: Next program counter
    """

    kind: str
    pc: int


@dataclass(frozen=True)
class HaltDiverged(Halt):
    """Program halted because of an unconstrained branch"""

    halt1: Halt
    halt2: Halt
    guard1: Expression
    guard2: Expression


# ***********************************************
# *** Helper: Describe an illegal instruction ***
# ***********************************************
@dataclass(frozen=True)
class IllegalInstr:
    """Root class for illegal instructions descriptions.

    See its subclasses for the possible results.
    """

    pass


@dataclass(frozen=True)
class IllegalInstrNoDecode(IllegalInstr):
    """Description of an invalid instruction.

    angr was unable to disassemble this instruction.
    This is either gibberish injected purposefully
    to cause an illtrap, or you tried to execute data.

    This is an inaccurate result, since the various
    diassemblers used by angr don't always cover
    the entire ISA.

    Attributes:
        mem: String representing 16 bytes of memory at the instruction pointer.
    """

    mem: str


@dataclass(frozen=True)
class IllegalInstrConfirmed(IllegalInstr):
    """Description of a valid but illegal instruction.

    angr disassembled it successfully,
    but the lifter couldn't model it.

    This is an inaccurate result,
    since the Vex lifter only supports subsets of each ISA
    relevant to user-space code,
    and may not support more exotic extensions.
    """

    instr: str


@dataclass(frozen=True)
class IllegalInstrUnconfirmed(IllegalInstr):
    """Description of a valid and legal instruction.

    angr disassembled and lifted this instruction without issue;
    it's not obviously illegal.

    This is an inaccurate result,
    since the Vex lifter isn't always consistent about how
    it models faulting instructions.
    """

    instr: str


@dataclass(frozen=True)
class Diagnosis:
    """Root class of all diagnoses"""

    pass


# ***************************************
# *** Diagnosis for Early termination ***
# ***************************************


@dataclass(frozen=True)
class DiagnosisEarly(Diagnosis):
    """Diagnosis pass terminated early

    See subclasses for specific diagnoses.

    Attributes:
        index: Index into the trace where the disruption happened.
    """

    index: int


@dataclass(frozen=True)
class DiagnosisEarlyDiverge(DiagnosisEarly):
    """Diagnosis pass did not follow the trace precisely.

    Attributes:
        pc: Program counter encountered instead of the expected PC.
    """

    pc: int


@dataclass(frozen=True)
class DiagnosisEarlyHalt(DiagnosisEarly):
    """Diagnosis pass terminated due to halt condition.

    Attributes:
        halt: Analysis of why diagnosis halted.
    """

    halt: Halt


@dataclass(frozen=True)
class DiagnosisEarlyIllegal(DiagnosisEarly):
    """Diagnosis pass terminated due to an illegal instruction.

    Attributes:
        illegal: Analysis of illegal instruction
    """

    illegal: IllegalInstr


# ***********************************
# *** Diagnosis for Out of bounds ***
# ***********************************


@dataclass(frozen=True)
class DiagnosisOOB(Diagnosis):
    """Parent class for halt diagnoses.

    See subclasses for specific diagnoses.
    """

    pass


@dataclass(frozen=True)
class DiagnosisOOBConfirmed(DiagnosisOOB):
    """Diagnosis pass registered a halt at the expected point in the trace.

    Attributes:
        halt: Analysis of why diagnosis halted.
    """

    halt: Halt


@dataclass(frozen=True)
class DiagnosisOOBUnconfirmed(DiagnosisOOB):
    """Diagnosis pass did not register a halt at the expected point in the trace."""

    pass


# *****************************************
# *** Diagnosis for illegal instruction ***
# *****************************************


@dataclass(frozen=True)
class DiagnosisIllegal(Diagnosis):
    """Diagnosis for an illegal instruction fault

    Attributes:
        illegal: Description of the illegal instruction
    """

    illegal: IllegalInstr


# **************************
# *** Diagnosis for trap ***
# **************************


@dataclass(frozen=True)
class DiagnosisTrap(Diagnosis):
    """Diagnosis for an unhandled trap.

    angr is very user-space focused,
    and really doesn't model fault conditions
    beyond those already handled by
    memory failures or illegal instructions.

    This just indicates it reached the same state
    as Unicorn did.
    """

    pass


# **********************************
# *** Diagnosis for memory error ***
# **********************************


@dataclass(frozen=True)
class DiagnosisMemory(Diagnosis):
    """Diagnosis for a memory error

    Attributes:
        is_hook: True if this is suspected to be a hook.
        safe_operands: Operands I don't have anything against
        unmapped_operands: Operands whose results map to an unmapped address
        unconstrained_operands: Operands that depends on uninitialized data
    """

    is_hook: bool
    safe_operands: typing.Dict[typing.Any, typing.Tuple[Expression, int]]
    unmapped_operands: typing.Dict[typing.Any, typing.Tuple[Expression, int]]
    unconstrained_operands: typing.Dict[typing.Any, Expression]
    unsat_operands: typing.Dict[typing.Any, Expression]


# *************
# *** Hints ***
# *************


@dataclass(frozen=True)
class TriageHint(hinting.Hint):
    """Base hint for crash triage results.

    Attributes:
       trace: List of program counters explored by concrete execution
    """

    trace: typing.List[int]

    def to_json(self):
        return dict()


@dataclass(frozen=True)
class TriageNoCrash(TriageHint):
    """Triage did not encounter a crash."""

    pass


@dataclass(frozen=True)
class TriageNormalExit(TriageNoCrash):
    """Triage exited normally via an exit point."""

    pass


@dataclass(frozen=True)
class TriageTooLong(TriageNoCrash):
    """Triage exhausted the allowed number of steps."""

    pass


@dataclass(frozen=True)
class TriageCrash(TriageHint):
    """Triage encountered a crash."""

    pass


@dataclass(frozen=True)
class TriageOOB(TriageCrash):
    """Triage exited because program went out of bounds

    Attributes:
        diagnosis: Description of the diagnosis.
    """

    diagnosis: typing.Union[DiagnosisEarly, DiagnosisOOB]


@dataclass(frozen=True)
class TriageIllegal(TriageCrash):
    """Triage exited because of an illegal instruction.

    Attributes:
        diagnosis: Description of the diagnosis.
    """

    diagnosis: typing.Union[DiagnosisEarly, DiagnosisIllegal]


@dataclass(frozen=True)
class TriageTrap(TriageCrash):
    """Triage exited because of an uncaught trap.

    Attributes:
        diagnosis: Description of the diagnosis.
    """

    diagnosis: typing.Union[DiagnosisEarly, DiagnosisTrap]


class MemoryAccess(enum.Enum):
    READ = "read"
    WRITE = "write"
    FETCH = "fetch"


@dataclass(frozen=True)
class TriageMemory(TriageCrash):
    """Triage exited because of a memory error.

    Attributes:
        diagnosis: Description of the diagnosis.
    """

    access: MemoryAccess
    diagnosis: typing.Union[DiagnosisEarly, DiagnosisMemory]


__all__ = [
    "Diagnosis",
    "DiagnosisEarly",
    "DiagnosisEarlyDiverge",
    "DiagnosisEarlyHalt",
    "DiagnosisEarlyIllegal",
    "DiagnosisIllegal",
    "DiagnosisMemory",
    "DiagnosisOOB",
    "DiagnosisOOBConfirmed",
    "DiagnosisOOBUnconfirmed",
    "DiagnosisTrap",
    "Halt",
    "HaltDeadended",
    "HaltDiverged",
    "HaltUnconstrained",
    "IllegalInstr",
    "IllegalInstrNoDecode",
    "IllegalInstrConfirmed",
    "IllegalInstrUnconfirmed",
    "MemoryAccess",
    "TriageCrash",
    "TriageIllegal",
    "TriageMemory",
    "TriageNoCrash",
    "TriageNormalExit",
    "TriageOOB",
    "TriageTooLong",
    "TriageTrap",
]
