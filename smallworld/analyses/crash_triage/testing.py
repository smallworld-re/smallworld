import logging
import typing

from ... import exceptions, hinting, state
from .. import analysis
from .crash_triage import CrashTriage
from .hints import (
    Diagnosis,
    Halt,
    IllegalInstr,
    MemoryAccess,
    TriageHint,
    TriageIllegal,
    TriageMemory,
    TriageNormalExit,
    TriageOOB,
    TriageTooLong,
    TriageTrap,
)
from .printer import CrashTriagePrinter

logger = logging.getLogger(__name__)


class CrashTriageVerification(analysis.Analysis):
    """Verification hooking for CrashTriage.

    This confirms that a use of the crash triage analyzer
    produces a specific equivalence class of cause
    and diagnosis.

    It's mostly useful for testing purposes;
    I didn't want to rewrite this in each
    of the integration test scripts.
    """

    name = "crash-triage-verification"
    description = "Test harness for crash triage"
    version = "0.0.1"

    def __init__(
        self,
        *args,
        max_steps: int = -1,
        hint_type: typing.Optional[typing.Type[TriageHint]] = None,
        hint_attrs: typing.Optional[typing.Dict[str, typing.Any]] = None,
        diagnosis_type: typing.Optional[typing.Type[Diagnosis]] = None,
        halt_type: typing.Optional[typing.Type[Halt]] = None,
        halt_kind: typing.Optional[str] = None,
        halt_target: typing.Optional[str] = None,
        illegal_type: typing.Optional[typing.Type[IllegalInstr]] = None,
        mem_access: typing.Optional[MemoryAccess] = None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.max_steps = max_steps
        self.hint_type = hint_type
        self.diagnosis_type = diagnosis_type
        self.halt_type = halt_type
        self.halt_kind = halt_kind
        self.halt_target = halt_target
        self.illegal_type = illegal_type
        self.mem_access = mem_access

    def _handle_hint(self, hint: hinting.Hint):
        if self.hint_type is not None and not isinstance(hint, self.hint_type):
            raise exceptions.AnalysisError(
                f"Expected hint {self.hint_type}, got {type(hint)}"
            )

        if self.diagnosis_type is not None:
            if not hasattr(hint, "diagnosis"):
                raise exceptions.AnalysisError(
                    f"Expected diagnosis {self.diagnosis_type}; {type(hint)} has no diagnosis"
                )
            elif not isinstance(hint.diagnosis, self.diagnosis_type):
                raise exceptions.AnalysisError(
                    f"Expected diagnosis {self.diagnosis_type}, got {type(hint.diagnosis)}"
                )

        if self.halt_type is not None:
            if not hasattr(hint, "diagnosis"):
                raise exceptions.AnalysisError(
                    f"Expected halt {self.halt_type}; {type(hint)} has no diagnosis"
                )
            elif not hasattr(hint.diagnosis, "halt"):
                raise exceptions.AnalysisError(
                    f"Expected halt {self.halt_type}; {type(hint.diagnosis)} has no halt"
                )
            elif not isinstance(hint.diagnosis.halt, self.halt_type):
                raise exceptions.AnalysisError(
                    f"Expected halt {self.halt_type}, got {type(hint.diagnosis.halt)}"
                )

            if self.halt_kind is not None and not hasattr(hint.diagnosis.halt, "kind"):
                raise exceptions.AnalysisError(
                    f"Expected halt to have kind {self.halt_kind}; {type(hint.diagnosis.halt)} has no kind"
                )
            elif (
                self.halt_kind is not None
                and hasattr(hint.diagnosis.halt, "kind")
                and hint.diagnosis.halt.kind != self.halt_kind
            ):
                raise exceptions.AnalysisError(
                    f"Expected halt to have kind {self.halt_kind}, got {hint.diagnosis.halt.kind}"
                )

            if self.halt_target is not None and not hasattr(
                hint.diagnosis.halt, "target"
            ):
                raise exceptions.AnalysisError(
                    f"Expected halt to have target {self.halt_target}; {type(hint.diagnosis.halt)} has no target"
                )
            elif (
                self.halt_target is not None
                and hasattr(hint.diagnosis.halt, "target")
                and hint.diagnosis.halt.target != self.halt_target
            ):
                raise exceptions.AnalysisError(
                    f"Expected halt to have target {self.halt_target}, got {hint.diagnosis.halt.target}"
                )

        elif self.halt_kind is not None:
            raise exceptions.AnalysisError(
                f"Specified halt kind {self.halt_kind}, but no halt expected"
            )

        elif self.halt_target is not None:
            raise exceptions.AnalysisError(
                f"Specified halt target {self.halt_target}. but no halt expected"
            )

        if self.illegal_type is not None:
            if not hasattr(hint, "diagnosis"):
                raise exceptions.AnalysisError(
                    f"Expected illegal {self.illegal_type}; {type(hint)} has no diagnosis"
                )
            elif not hasattr(hint.diagnosis, "illegal"):
                raise exceptions.AnalysisError(
                    f"Expected illegal {self.illegal_type}; {type(hint.diagnosis)} has no illegal"
                )
            elif not isinstance(hint.diagnosis.illegal, self.illegal_type):
                raise exceptions.AnalysisError(
                    f"Expected illegal {self.illegal_type}, got {type(hint.diagnosis.illegal)}"
                )

        if self.mem_access is not None:
            if not isinstance(hint, TriageMemory):
                raise exceptions.AnalysisError(
                    f"Expected access {self.mem_access.value}; {type(hint)} has no access"
                )
            elif hint.access != self.mem_access:
                raise exceptions.AnalysisError(
                    f"Expected access {self.mem_access.value}, got {hint.access.value}"
                )

    def run(self, machine: state.Machine):
        CrashTriagePrinter(self.hinter).run(machine)

        self.hinter.register(TriageIllegal, self._handle_hint)
        self.hinter.register(TriageMemory, self._handle_hint)
        self.hinter.register(TriageNormalExit, self._handle_hint)
        self.hinter.register(TriageOOB, self._handle_hint)
        self.hinter.register(TriageTooLong, self._handle_hint)
        self.hinter.register(TriageTrap, self._handle_hint)

        CrashTriage(self.hinter, max_steps=self.max_steps).run(machine)


__all__ = ["CrashTriageVerification"]
