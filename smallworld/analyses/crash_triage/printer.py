import logging
import typing

from ... import hinting, state
from .. import analysis
from .hints import (
    DiagnosisEarly,
    DiagnosisEarlyDiverge,
    DiagnosisEarlyHalt,
    DiagnosisEarlyIllegal,
    DiagnosisIllegal,
    DiagnosisMemory,
    DiagnosisOOB,
    DiagnosisOOBConfirmed,
    DiagnosisOOBUnconfirmed,
    DiagnosisTrap,
    Expression,
    Halt,
    HaltDeadended,
    HaltDiverged,
    HaltUnconstrained,
    IllegalInstr,
    IllegalInstrConfirmed,
    IllegalInstrNoDecode,
    IllegalInstrUnconfirmed,
    TriageIllegal,
    TriageMemory,
    TriageNormalExit,
    TriageOOB,
    TriageTooLong,
    TriageTrap,
)

log = logging.getLogger(__name__)


class CrashTriagePrinter(analysis.Analysis):
    name = "crash-triage-printer"
    description = "Pretty-print the results from crash triage"
    version = "0.0.1"

    def print_expression(self, expr: Expression) -> None:
        log.warning(f"Relevant expression: {expr.expr}")
        if expr.usr_labels:
            log.warning(f"Depends on user-labeled data: {expr.usr_labels}")
        if expr.init_reg_labels:
            log.warning(f"Depends on initialized registers: {expr.init_reg_labels}")
        if expr.init_mem_labels:
            log.warning(f"Depends on initialized memory: {expr.init_mem_labels}")
        if expr.unk_reg_labels:
            log.warning(f"Depends on uninitialized registers: {expr.unk_reg_labels}")
        if expr.unk_mem_labels:
            log.warning(f"Depends on uninitialized memory: {expr.unk_mem_labels}")
        if expr.unk_unk_labels:
            log.warning(f"Depends on unknown state: {expr.unk_unk_labels}")

    def print_illegal_instr(self, pc: int, illegal: IllegalInstr) -> None:
        if isinstance(illegal, IllegalInstrNoDecode):
            log.warning(f"Code at {pc:x} is undecodable: {illegal.mem}")
        elif isinstance(illegal, IllegalInstrConfirmed):
            log.warning(
                f"Code at {pc:x} is a known faulting instruction: {illegal.instr}"
            )
        elif isinstance(illegal, IllegalInstrUnconfirmed):
            log.warning(f"Code at {pc:x} appears decodable: {illegal.instr}")
            log.warning("This analysis may not be acurate; check the docs for this ISA")
        else:
            log.error(f"Unknown illegal instruction report: {illegal}")

    def print_halt(self, pc: int, halt: Halt) -> None:
        if isinstance(halt, HaltUnconstrained):
            log.warning(f"Halted due to unbounded {halt.kind}")
            self.print_expression(halt.expr)
        elif isinstance(halt, HaltDeadended):
            log.warning(f"Halted due to {halt.kind} at {halt.pc:x}")
        elif isinstance(halt, HaltDiverged):
            log.warning(f"Halted due to diverging state after {pc:x}")

    def print_diag_early(
        self, pc: int, trace: typing.List[int], diagnosis: DiagnosisEarly
    ) -> None:
        if isinstance(diagnosis, DiagnosisEarlyDiverge):
            log.warning("Triage did not follow the initial trace")
            log.warning(
                f"Expected {pc:x} at step {diagnosis.index}, got {diagnosis.pc}"
            )
        elif isinstance(diagnosis, DiagnosisEarlyHalt):
            log.warning(
                f"Triage halted early at step {diagnosis.index} ({trace[diagnosis.index]:x})"
            )
            self.print_halt(trace[diagnosis.index], diagnosis.halt)
        elif isinstance(diagnosis, DiagnosisEarlyIllegal):
            log.warning(
                f"Triage encountered an illegal instruciton at step {diagnosis.index} ({trace[diagnosis.index]:x})"
            )
            self.print_illegal_instr(trace[diagnosis.index], diagnosis.illegal)

    def print_diag_oob(self, pc: int, diagnosis: DiagnosisOOB) -> None:
        if isinstance(diagnosis, DiagnosisOOBUnconfirmed):
            log.warning("Triage did not encounter the same stop as the original trace")
        elif isinstance(diagnosis, DiagnosisOOBConfirmed):
            self.print_halt(pc, diagnosis.halt)

    def print_diag_trap(self, pc: int, diagnosis: DiagnosisTrap) -> None:
        pass

    def print_diag_memory(self, pc: int, diagnosis: DiagnosisMemory) -> None:
        pass

    def print_crash_illegal(self, hint: hinting.Hint) -> None:
        assert isinstance(hint, TriageIllegal)
        pc = hint.trace[-1]
        log.warning(f"Crash caused by illegal instruction at {pc:x}")
        if isinstance(hint.diagnosis, DiagnosisEarly):
            self.print_diag_early(pc, hint.trace, hint.diagnosis)
        elif isinstance(hint.diagnosis, DiagnosisIllegal):
            self.print_illegal_instr(pc, hint.diagnosis.illegal)
        else:
            raise TypeError(f"Expected DiagnosisIllegal, got {type(hint.diagnosis)}")

    def print_crash_normal(self, hint: hinting.Hint) -> None:
        assert isinstance(hint, TriageNormalExit)
        pc = hint.trace[-1]
        log.warning(f"No crash; Code exited normally after {pc:x}")

    def print_crash_too_long(self, hint: hinting.Hint) -> None:
        assert isinstance(hint, TriageTooLong)
        log.warning("No crash; Emulation ran out of steps")

    def print_crash_oob(self, hint: hinting.Hint) -> None:
        assert isinstance(hint, TriageOOB)
        pc = hint.trace[-1]
        log.warning(f"Crash caused by out of bounds execution after {pc:x}")
        if isinstance(hint.diagnosis, DiagnosisEarly):
            self.print_diag_early(pc, hint.trace, hint.diagnosis)
        elif isinstance(hint.diagnosis, DiagnosisOOB):
            self.print_diag_oob(pc, hint.diagnosis)
        else:
            raise TypeError(f"Expected DiagnosisOOB, got {type(hint.diagnosis)}")

    def print_crash_trap(self, hint: hinting.Hint) -> None:
        assert isinstance(hint, TriageTrap)
        pc = hint.trace[-1]
        log.warning(f"Crash caused by an unhandled trap at {pc:x}")
        if isinstance(hint.diagnosis, DiagnosisEarly):
            self.print_diag_early(pc, hint.trace, hint.diagnosis)
        elif isinstance(hint.diagnosis, DiagnosisTrap):
            self.print_diag_trap(pc, hint.diagnosis)
        else:
            raise TypeError(f"Expected DiagnosisTrap, got {type(hint.diagnosis)}")

    def print_crash_memory(self, hint: hinting.Hint) -> None:
        assert isinstance(hint, TriageMemory)
        pc = hint.trace[-1]
        log.warning(f"Crash caused by a memory error at {pc:x}")
        if isinstance(hint.diagnosis, DiagnosisEarly):
            self.print_diag_early(pc, hint.trace, hint.diagnosis)
        elif isinstance(hint.diagnosis, DiagnosisMemory):
            self.print_diag_memory(pc, hint.diagnosis)
        else:
            raise TypeError(f"Expected DiagnosisMemory, got {type(hint.diagnosis)}")

    def run(self, machine: state.Machine):
        self.hinter.register(TriageIllegal, self.print_crash_illegal)
        self.hinter.register(TriageMemory, self.print_crash_memory)
        self.hinter.register(TriageNormalExit, self.print_crash_normal)
        self.hinter.register(TriageOOB, self.print_crash_oob)
        self.hinter.register(TriageTooLong, self.print_crash_too_long)
        self.hinter.register(TriageTrap, self.print_crash_trap)
