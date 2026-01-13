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
class HaltUnconstrained(Halt):
    kind: str
    expr: Expression


@dataclass(frozen=True)
class HaltDeadended(Halt):
    kind: str
    pc: int


@dataclass(frozen=True)
class HaltDiverged(Halt):
    halt1: Halt
    halt2: Halt
    guard1: Expression
    guard2: Expression


# ***********************************************
# *** Helper: Describe an illegal instruction ***
# ***********************************************
@dataclass(frozen=True)
class IllegalInstr:
    pass


@dataclass(frozen=True)
class IllegalInstrNoDecode(IllegalInstr):
    mem: str


@dataclass(frozen=True)
class IllegalInstrConfirmed(IllegalInstr):
    instr: str


@dataclass(frozen=True)
class IllegalInstrUnconfirmed(IllegalInstr):
    instr: str


# ***************************************
# *** Diagnosis for Early termination ***
# ***************************************


@dataclass(frozen=True)
class DiagnosisEarly:
    """Diagnosis pass terminated early

    Attributes:
        index: Index into the trace where the disruption happened/
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
class DiagnosisOOB:
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
class DiagnosisIllegal:
    """Diagnosis for an illegal instruction.

    Attributes:
        illegal: Description of the illegal instruction
    """

    illegal: IllegalInstr


# **************************
# *** Diagnosis for trap ***
# **************************


@dataclass(frozen=True)
class DiagnosisTrap:
    """Diagnosis for an unhandled trap.

    Don't know how to get details;
    just confirms that diagnosis was able to reach the same point.
    """

    pass


# **********************************
# *** Diagnosis for memory error ***
# **********************************


@dataclass(frozen=True)
class DiagnosisMemory:
    """Diagnosis for a memory error"""

    pass


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
    pass


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


@dataclass(frozen=True)
class TriageMemory(TriageCrash):
    """Triage exited because of a memory error.

    Attributes:
        diagnosis: Description of the diagnosis.
    """

    diagnosis: typing.Union[DiagnosisEarly, DiagnosisMemory]


__all__ = [
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
    "TriageCrash",
    "TriageIllegal",
    "TriageMemory",
    "TriageNoCrash",
    "TriageNormalExit",
    "TriageOOB",
    "TriageTooLong",
    "TriageTrap",
]
