import copy
import dataclasses
import enum
import logging
import typing

import angr

from ... import emulators, exceptions, platforms, state
from .. import analysis
from .hints import (  # DiagnosisEarlyDiverge,; DiagnosisIllegal,; DiagnosisMemory,; DiagnosisOOB,; DiagnosisOOBConfirmed,; DiagnosisOOBUnconfirmed,; HaltDeadended,; HaltDiverged,; HaltUnconstrained,; IllegalInstrConfirmed,; IllegalInstrNoDecode,; IllegalInstrUnconfirmed,
    DiagnosisEarly,
    DiagnosisEarlyHalt,
    DiagnosisEarlyIllegal,
    DiagnosisTrap,
    TriageHint,
    TriageIllegal,
    TriageMemory,
    TriageNormalExit,
    TriageOOB,
    TriageTooLong,
    TriageTrap,
)

log = logging.getLogger(__name__)
print(__name__)


class CrashCause(enum.Enum):
    NULL = 0
    OOB = 1
    ILLEGAL = 2
    TRAP = 3
    MEM = 4


@dataclasses.dataclass
class CrashResults:
    trace: typing.List[int]
    cause: CrashCause
    mem_operands: typing.Optional[typing.List[typing.Any]]


class CrashTriage(analysis.Analysis):
    name = "crash-triage"
    description = "Diagnose a crashing harness"
    version = "0.0.1"

    def __init__(self, *args, max_steps: int = -1, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_steps: int = max_steps
        self.og_labels: typing.Set[str] = set()
        self.reg_labels: typing.Set[str] = set()
        self.mem_labels: typing.Set[str] = set()

    def _instrument_machine(self, machine: state.Machine):
        # Label everything initialized.
        self.og_labels.clear()
        self.reg_labels.clear()
        self.mem_labels.clear()
        platdef = platforms.PlatformDef.for_platform(machine.get_platform())

        for x in machine:
            if isinstance(x, state.cpus.CPU):
                for reg in x:
                    if isinstance(reg, state.RegisterAlias):
                        continue
                    if reg.get_content() is None:
                        continue
                    if reg.name == platdef.pc_register:
                        # Do not make the PC register symbolic.  Badness ensues.
                        continue
                    if reg.get_label() is None:
                        print(f"Renaming {reg.name}")
                        reg.set_label(reg.name)
                        self.reg_labels.add(reg.name)
                    else:
                        self.og_labels.add(reg.get_label())

            elif isinstance(x, state.memory.Memory):
                for off, val in x.items():
                    if hasattr(x, "bounds") and x.bounds.contains_value(
                        x.address + off
                    ):
                        # This is an executable segment.
                        # Labeling code reduces angr's performance to almost a second per step,
                        # since it needs to use the solver to concretize the memory.
                        #
                        # This will limit introspection into decisions based off of
                        # data in any R/X segments, but since it's read-only I'm not too worried.
                        continue
                    label = val.get_label()
                    if label is None:
                        label = f"memory_{x.address + off:x}"
                        val.set_label(label)
                        self.mem_labels.add(label)
                    else:
                        self.og_labels.add(label)

            # Anything else is a hook.  They don't need labels.

    def _get_crash(self, machine: state.Machine) -> typing.Optional[CrashResults]:
        # Create and configure a Unicorn emulator.
        emu = emulators.UnicornEmulator(machine.get_platform())
        machine.apply(emu)

        hint: TriageHint

        trace: typing.List[int] = list()
        cause: CrashCause
        mem_operands: typing.Optional[typing.List[typing.Any]] = None

        # Run the emulator without the wrapper,
        # so I can get all the exceptions.
        try:
            idx = 0
            while self.max_steps > 0 and idx < self.max_steps:
                pc = emu.read_register("pc")
                # There is something wrong with Unicorn's bounds check
                if not emu._bounds.contains_value(pc):
                    raise exceptions.EmulationBounds

                log.debug(f"Stepping through {pc:x}")
                trace.append(pc)
                emu.step()
                idx += 1

            log.warning(
                f"No crash found after {self.max_steps} steps.  Try a bigger limit?"
            )
            hint = TriageTooLong(
                message=f"No crash found after {self.max_steps} steps.", trace=trace
            )
            self.hinter.send(hint)
            return None
        except exceptions.EmulationExitpoint:
            # Normal exit.  No crash?
            log.warning("Exited normally; no crash")
            hint = TriageNormalExit(message="Exited normally; no crash", trace=trace)
            self.hinter.send(hint)
            return None
        except exceptions.EmulationBounds:
            # Out of Bounds.  This could be a crash or a normal exit.
            # For now, it's a crash by fiat.
            log.debug("Out of Bounds")
            cause = CrashCause.OOB
        except exceptions.EmulationExecInvalidFailure as e:
            # Tried to execute an invalid instruction.
            log.debug(f"Invalid instruction at {e.pc:x}")
            cause = CrashCause.ILLEGAL
        except exceptions.EmulationExecExceptionFailure as e:
            # Unhandled exception/interrupt/trap/whatever your ISA calls it.
            log.debug(f"Trap at {e.pc:x}")
            cause = CrashCause.TRAP
        except exceptions.EmulationMemoryFailure as e:
            # Something went very wrong doing the memories.
            log.debug(f"Memory exception at {e.pc:x}: {e.operands}")
            cause = CrashCause.MEM
            mem_operands = e.operands

        return CrashResults(trace, cause, mem_operands)

    def _check_trace(
        self, i: int, trace: typing.List[int], emu: emulators.AngrEmulator
    ):
        epc = trace[i]
        apc = emu.read_register("pc")
        log.debug(f"Stepping through {apc:x}")
        if epc != apc:
            log.warning(f"Unexpected PC at step {i}: expected {epc:x}, got {apc:x}")
            return False
        return True

    def _diagnose_expression(self, emu, expr):
        og_labels: typing.Set[str] = set()
        reg_labels: typing.Set[str] = set()
        mem_labels: typing.Set[str] = set()
        unk_labels: typing.Set[str] = set()
        for label in expr.variables:
            if label in self.og_labels:
                og_labels.add(label)
            elif label in self.reg_labels:
                reg_labels.add(label)
            elif label in self.mem_labels:
                mem_labels.add(label)
            else:
                unk_labels.add(label)

        if og_labels:
            log.warning(f"Depends on user-provided data: {og_labels}")
        if reg_labels:
            log.warning(f"Depends on initialized registers: {og_labels}")
        if mem_labels:
            mem_labels = set(map(lambda x: x[4:]))
            log.warning(f"Depends on initialized memory segments: {mem_labels}")
        if unk_labels:
            unk_reg_labels = set()
            unk_mem_labels = set()
            unk_unk_labels = set()
            for label in unk_labels:
                if label.startswith("reg"):
                    label_arr = label.split("_")
                    offset = int(label_arr[1], 16)
                    size = int(label_arr[3]) / 8
                    name = emulators.angr.utils.reg_name_from_offset(
                        emu.machdef.angr_arch, offset, size
                    )
                    unk_reg_labels.add(name)
                elif label.startswith("mem"):
                    label_arr = label.split("_")
                    unk_mem_labels.add(label_arr[1])
                else:
                    unk_unk_labels.add(label)
            if unk_reg_labels:
                log.warning(f"Depends on uninitialized registers: {unk_reg_labels}")
            if unk_mem_labels:
                log.warning(
                    f"Depends on uninitialized memory segments: {unk_mem_labels}"
                )
            if unk_unk_labels:
                log.warning(
                    f"Depends on unrecognized uninitialized state: {unk_unk_labels}"
                )

    def _diagnose_unconstrained(
        self, emu: emulators.AngrEmulator, state: angr.SimState, pc: int, expected: bool
    ):
        target = state._ip

        # Recover the Vex that got us here.
        old_state = emu.state
        emu.state = state
        emu.write_register("pc", pc)
        vex = state.block(opt_level=0).vex
        emu.state = old_state
        # Vex only allows indirect jumps as default block exits.
        # We can look at the default jumpkind for this block
        # to tell us
        if vex.jumpkind == "Ijk_Ret":
            log.warning("Caused by an unbounded return.")
        elif vex.jumpkind == "Ijk_Call":
            log.warning("Caused by an unbounded indirect function call.")
        elif vex.jumpkind in ("Ijk_Boring", "Ijk_Privileged", "Ijk_Yield"):
            log.warning("Caused by an unbounded indirect jump.")
        else:
            log.error(f"Unexpected cause: {vex.jumpkind}")

        log.warning(f"Jump target expression: {target}")
        self._diagnose_expression(emu, target)

    def _diagnose_deadended(
        self, emu: emulators.AngrEmulator, state: angr.SimState, expected: bool
    ):
        ip = state._ip.concrete_value
        if not emu.state.scratch.memory_map.contains_value(ip):
            log.warning(f"Execution entered unmapped memory at {ip:x}")
            return True
        elif (
            not emu.state.scratch.bounds.is_empty()
            and not emu.state.scratch.bounds.contains_value(ip)
        ):
            log.warning(f"Execution went out of bounds at {ip:x}")
            return True
        elif ip in emu.state.scratch.exit_points:
            log.warning(f"Execution hit an exit point at {ip:x}")
            return True
        elif expected:
            log.warning(f"No clear cause for deadended state at {ip:x}")

        return False

    def _diagnose_stop(self, emu: emulators.AngrEmulator, pc: int, expected: bool):
        # Cases:
        # - Single unconstrained state:
        #   - Return out of context?
        #   - Uninitialized function pointer?
        # - Single deadended state:
        #   - Unmapped code
        #   - OOB
        #   - Exitpoint
        # - Divergent state:
        #   - Check if a path should deadend.  Emulator halts before that check is made.
        #   - If this is unexpected, what is the last guard conditioned on?
        if len(emu.mgr.unconstrained) > 0:
            # Unconstrained state; program counter was unbounded.
            log.warning(f"Stopped due to unbound PC after {pc:x}")
            (state,) = emu.mgr.unconstrained
            self._diagnose_unconstrained(emu, state, pc, expected)

        elif len(emu.mgr.deadended) > 0:
            # Single deadended state
            log.warning(f"Stopped due to execution limits after {pc:x}")
            (state,) = emu.mgr.deadended
            self._diagnose_deadended(emu, state, expected)

        elif len(emu.mgr.active) > 1:
            # Divergent state.
            log.warning(f"State diverged after {pc:x}")

            state1, state2 = emu.mgr.active

            # SmallWorld aborts before categorizing divergent states.
            # These may not only diverge unexpectedly,
            # but may lead to deadended or unconstrained states.
            if state1._ip.symbolic:
                log.warning("State at {state1._ip} is unconstrained")
                self._diagnose_unconstrained(emu, state1, pc, expected)
            else:
                self._diagnose_deadended(emu, state1, False)

            if state1._ip.symbolic:
                log.warning("State at {state2._ip} is unconstrained")
                self._diagnose_unconstrained(emu, state2, pc, expected)
            else:
                self._diagnose_deadended(emu, state2, False)

            log.warning(f"Guard for {state1._ip}: {state1.scratch.guard}")
            self._diagnose_expression(emu, state1.scratch.guard)
            log.warning(f"Guard for {state2._ip}: {state2.scratch.guard}")
            self._diagnose_expression(emu, state2.scratch.guard)

    def _diagnose_oob(self, emu: emulators.AngrEmulator, crash: CrashResults):
        try:
            emu.step()
            # Didn't trigger.  I wonder why.
            log.warning(
                f"Expected emulation to stop at {crash.trace[-1]:x}, but it didn't."
            )
            return
        except exceptions.EmulationStop:
            pass

        # Handle it the same way, just with expected stops.
        self._diagnose_stop(emu, crash.trace[-1], True)

    def _diagnose_illegal(self, emu: emulators.AngrEmulator, pc: int, expected: bool):
        block = emu.state.block(opt_level=0, strict_block_end=True)

        disas = block.disassembly
        if disas is not None and len(disas.insns) > 0:
            insn = disas.insns[0]
        else:
            insn = None

        if block.vex.jumpkind == "Ijk_NoDecode":
            if insn is not None:
                log.warning(f"Instruction at {pc:x} is illegal: {insn}")
            else:
                insn_mem = emu.read_memory_symbolic(pc, 16)
                log.warning(f"Instruction at {pc:x} is untranslatable: {insn_mem}")
        else:
            log.warning(f"Instruction at {pc:x} appears fine to vex: {insn}")
            log.warning(
                "vex may not be fully accurate.  Please consult relevant ISA docs to confirm."
            )

    def _diagnose_trap(self, emu: emulators.AngrEmulator, crash: CrashResults):
        block = emu.state.block(opt_level=0, strict_block_end=True)

        disas = block.disassembly
        if disas is not None and len(disas.insns) > 0:
            insn = disas.insns[0]
        else:
            insn = None

        if insn is not None:
            log.warning(f"Unicorn reported a trap at {insn}")
            log.warning("It's extremely unlikely angr will capture this behavior.")
        else:
            log.warning(
                f"Unicorn reported a trap at {crash.trace[-1]:x}; instruction is undecodable."
            )
        return DiagnosisTrap()

    def _diagnose_mem(self, emu: emulators.AngrEmulator, crash: CrashResults):
        pc = crash.trace[-1]
        if crash.mem_operands is None:
            # This is almost certainly a memory error triggered by a model.
            log.warning(f"Memory error at {pc:x} has no associated cause.")

    def _get_early_hint(self, crash: CrashResults, diagnosis: DiagnosisEarly):
        if crash.cause is CrashCause.OOB:
            return TriageOOB(
                message="Crash caused by out of bounds execution",
                trace=crash.trace,
                diagnosis=diagnosis,
            )
        elif crash.cause is CrashCause.ILLEGAL:
            return TriageIllegal(
                message="Crash caused by illegal instruction",
                trace=crash.trace,
                diagnosis=diagnosis,
            )
        elif crash.cause is CrashCause.TRAP:
            return TriageTrap(
                message="Crash caused by unhandled trap",
                trace=crash.trace,
                diagnosis=diagnosis,
            )
        elif crash.cause is CrashCause.MEM:
            return TriageMemory(
                message="Crash caused by memory error",
                trace=crash.trace,
                diagnosis=diagnosis,
            )
        else:
            raise exceptions.AnalysisError(f"Unexpected crash cause {crash.cause}")

    def _diagnose(self, machine: state.Machine, crash: CrashResults):
        # Set up an angr emulator
        emu = emulators.AngrEmulator(machine.get_platform())
        emu.enable_linear()
        machine.apply(emu)
        emu.initialize()

        # Step through the emulator so I can tell if we're following the trace.
        for i in range(0, len(crash.trace) - 1):
            diagnosis = self._check_trace(i, crash.trace, emu)
            if diagnosis is not None:
                hint = self._get_early_hint(crash, diagnosis)
                self.hinter.send(hint)
                return

            try:
                emu.step()
            except exceptions.EmulationStop:
                # Emulator stopped early.
                log.warning(f"Unexpected stop after {crash.trace[i]:x}")

                halt = self._diagnose_stop(emu, crash.trace[i], False)
                diagnosis = DiagnosisEarlyHalt(index=i, halt=halt)
                hint = self._get_early_hint(crash, diagnosis)

                self.hinter.send(hint)
                return
            except exceptions.EmulationExecInvalidFailure:
                # Emulator encountered an unexpected illegal instruction.
                # Unicorn and angr have different ISA coverage,
                # so this isn't expected.
                log.warning(f"Unexpected illegal instruction at {crash.trace[i]:x}")

                illegal = self._diagnose_illegal(emu, crash.trace[i], False)
                diagnosis = DiagnosisEarlyIllegal(index=i, illegal=illegal)
                hint = self._get_early_hint(crash, diagnosis)

                self.hinter.send(hint)
                return

        # Test that we've actually reached the final problem instruction
        diagnosis = self._check_trace(len(crash.trace) - 1, crash.trace, emu)
        if diagnosis is not None:
            hint = self._get_early_hint(crash, diagnosis)
            self.hinter.send(hint)
            return

        # Diagnose the specific cause of the crash
        if crash.cause is CrashCause.OOB:
            diagnosis = self._diagnose_oob(emu, crash)
            hint = TriageOOB(
                message="Crash caused by out of bounds execution",
                trace=crash.trace,
                diagnosis=diagnosis,
            )
        elif crash.cause is CrashCause.ILLEGAL:
            diagnosis = self._diagnose_illegal(emu, crash.trace[-1], True)
            hint = TriageIllegal(
                message="Crash caused by illegal instruction",
                trace=crash.trace,
                diagnosis=diagnosis,
            )
        elif crash.cause is CrashCause.TRAP:
            diagnosis = self._diagnose_trap(emu, crash)
            hint = TriageTrap(
                message="Crash caused by unhandled trap",
                trace=crash.trace,
                diagnosis=diagnosis,
            )
        elif crash.cause is CrashCause.MEM:
            diagnosis = self._diagnose_mem(emu, crash)
            hint = TriageMemory(
                message="Crash caused by memory error",
                trace=crash.trace,
                diagnosis=diagnosis,
            )
        else:
            raise exceptions.AnalysisError(f"Unrecognized crash cause {crash.cause}")

        self.hinter.send(hint)

    def run(self, machine: state.Machine) -> None:
        # Copy the machine.  We will edit it.
        machine = copy.deepcopy(machine)

        self._instrument_machine(machine)
        results = self._get_crash(machine)
        if results is None:
            return
        self._diagnose(machine, results)
