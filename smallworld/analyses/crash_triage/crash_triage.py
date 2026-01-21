import copy
import dataclasses
import enum
import logging
import typing

import angr

from ... import emulators, exceptions, platforms, state
from .. import analysis
from .concretization import SimConcretizationStrategyFault, UnboundAddressError
from .hints import (
    DiagnosisEarly,
    DiagnosisEarlyDiverge,
    DiagnosisEarlyHalt,
    DiagnosisEarlyIllegal,
    DiagnosisEarlyMemory,
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
    HaltNoHalt,
    HaltUnconstrained,
    IllegalInstr,
    IllegalInstrConfirmed,
    IllegalInstrNoDecode,
    IllegalInstrUnconfirmed,
    MemoryAccess,
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
    MEM_READ = 4
    MEM_WRITE = 5
    MEM_FETCH = 6


@dataclasses.dataclass
class CrashResults:
    trace: typing.List[int]
    cause: CrashCause
    mem_operands: typing.Optional[typing.List[typing.Any]]


class CrashTriage(analysis.Analysis):
    """An analysis to ID potential causes of a crash.

    Concrete emulators like Unicorn and Panda
    are great at finding crashes, but they don't preserve
    enough data to really explain why a crash happened.
    You got a null pointer dereference.  Okay, why?
    Where did that null pointer come from?
    What was the program doing to cause it?

    On the other hand, angr's symbolic executor
    can provide extremely detailed machine-readable
    information about how the code and data
    reached a particular state,
    but getting it to identify crash conditions
    isn't always easy.

    The solution is a dual harness approach:

    - Run the harness once in Unicorn to get
      an immediate cause and execution trace
    - Run the harness again in angr to replay
      the execution trace.
    - Examine the final state from angr
      to get a diagnosis for the crash.

    Here are the kinds of hints produced by this analysis:

    TriageNormalExit:
        Execution exited at an exit point,
        indicating there was no crash.

    TriageNormalTooLong:
        Execution exceeded the specified maximum number of steps
        without encountering a crash.

    TriageOOB:
        Execution went out of bounds, or left mapped memory.

    TriageIllegal:
        Execution encountered an illegal instruction

    TriageTrap:
        Execution halted because of an unhandled
        hardware interrupt/trap/exception/fault

    TriageMemory:
        Execution halted because of an illegal memory access.
        This will include a field specifying the kind of access:
        read, write, or fetch.

    Each hint contains the execution trace it followed,
    as well as a diagnosis.
    The diagnosis will either contain details about the crash,
    or indicate that angr stopped before reaching it.
    """

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
                        # since it needs to use the solver to concretize up to an entire
                        # page of memory.  z3 is fast, but it's not that fast.
                        #
                        # This will limit introspection into decisions based off of
                        # data in any R/X segments, but since it's read-only I'm not too worried.
                        log.debug(
                            f"Skipping segment [{x.address + off:x} - {x.address + off + val.get_size():x}]; it's code"
                        )
                        continue
                    label = val.get_label()
                    if label is None:
                        label = f"memory_{x.address + off:x}"
                        log.debug(f"Adding memory label {label}")
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
            while self.max_steps < 0 or idx < self.max_steps:
                pc = emu.read_register("pc")
                # There is something wrong with Unicorn's bounds check
                if not emu._bounds.contains_value(pc):
                    raise exceptions.EmulationBounds

                log.info(f"Stepping through {pc:x}")
                trace.append(pc)
                emu.step()
                idx += 1

            log.debug(
                f"No crash found after {self.max_steps} steps.  Try a bigger limit?"
            )
            hint = TriageTooLong(
                message=f"No crash found after {self.max_steps} steps.", trace=trace
            )
            self.hinter.send(hint)
            return None
        except exceptions.EmulationExitpoint:
            # Normal exit.  No crash?
            log.debug("Exited normally; no crash")
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
        except exceptions.EmulationReadFailure as e:
            # Something went very wrong read the memories.
            log.debug(f"Memory read failure at {e.pc:x}: {e.operands}")
            cause = CrashCause.MEM_READ
            mem_operands = e.operands
        except exceptions.EmulationWriteFailure as e:
            # Something went very wrong read the memories.
            log.debug(f"Memory write failure at {e.pc:x}: {e.operands}")
            cause = CrashCause.MEM_WRITE
            mem_operands = e.operands
        except exceptions.EmulationFetchFailure as e:
            # Something went very wrong read the memories.
            log.debug(f"Memory fetch failure at {e.pc:x}: {e.operands}")
            cause = CrashCause.MEM_FETCH
            mem_operands = e.operands

        return CrashResults(trace, cause, mem_operands)

    def _check_trace(
        self, i: int, trace: typing.List[int], emu: emulators.AngrEmulator
    ) -> typing.Optional[DiagnosisEarlyDiverge]:
        epc = trace[i]
        ip = emu.read_register_symbolic("pc")
        apc = emu.state.solver.eval_one(ip)

        log.debug(f"Stepping through {apc:x} ({ip})")
        if epc != apc:
            log.debug(
                f"Unexpected PC at step {i}: expected {epc:x}, got {apc:x} ({ip})"
            )
            return DiagnosisEarlyDiverge(index=i, pc=apc)
        return None

    def _diagnose_expression(self, emu, expr):
        usr_labels: typing.Set[str] = set()
        reg_labels: typing.Set[str] = set()
        mem_labels: typing.Set[str] = set()
        mem_ref: typing.Optional[typing.Tuple[int, int]] = None
        unk_labels: typing.Set[str] = set()
        unk_reg_labels = set()
        unk_mem_labels = set()
        unk_unk_labels = set()

        # Check if this is a simple memory dereference
        # This will get represented as one of the following:
        #
        # - LSB: Reverse(memory_XXXXXXXX[b:a])
        # - MSB: memory_XXXXXXXX[b:a]
        #
        # where the referenced memory is [XXXXXXXX + a, XXXXXXXX + b)

        # Collect symbolic variable names
        for label in expr.variables:
            if label in self.og_labels:
                usr_labels.add(label)
            elif label in self.reg_labels:
                reg_labels.add(label)
            elif label in self.mem_labels:
                mem_labels.add(label)
            else:
                unk_labels.add(label)

        # Covnvert memory labels into addresses
        mem_labels = set(map(lambda x: "0x" + x.split("_")[1], mem_labels))

        if unk_labels:
            # Decode angr's uninitialized state naming convention
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

        if len(expr.variables) == 1:
            addr: typing.Optional[int] = None
            (label,) = expr.variables

            if "_" in label:
                addr_str = label.split("_")[1]
                if addr_str in mem_labels or addr_str in unk_mem_labels:
                    addr = int(addr_str, 16)

            if addr is not None:
                mem_expr = expr
                if mem_expr.op == "Reverse":
                    # This is reversed; it's little-endian
                    mem_expr = expr.args[0]

                start = 0
                end = 0

                if mem_expr.op == "BVS":
                    start = addr
                    end = addr + mem_expr.size() // 8

                elif mem_expr.op == "Extract":
                    # This is a slice of a larger chunk of memory
                    # Args in this case are end, start, original
                    #
                    # The nasty is that the indexes
                    # are relative to the LSB moving upward,
                    # so if you extract the first 8 bytes from a 0x1000 byte segment
                    # at 0x403000, you are referencing bits
                    # 0x7fc0 to 0x7fff.
                    b, a, mem_expr = mem_expr.args
                    size = mem_expr.size() // 8
                    start = addr + size - ((b + 1) // 8)
                    end = addr + size - (a // 8)

                if mem_expr.op == "BVS" and mem_expr.args[0] == label:
                    # This is a simple slice of a single memory region
                    mem_ref = (start, end)
                    log.debug(f"{mem_ref}")
        return Expression(
            expr=expr,
            usr_labels=usr_labels,
            init_reg_labels=reg_labels,
            init_mem_labels=mem_labels,
            init_mem_ref=mem_ref,
            unk_reg_labels=unk_reg_labels,
            unk_mem_labels=unk_mem_labels,
            unk_unk_labels=unk_unk_labels,
        )

    def _get_target_type(
        self, emu: emulators.AngrEmulator, state: angr.SimState, pc: int
    ) -> str:
        # Recover the vex that got us here
        old_state = emu.state
        emu.state = state
        emu.write_register("pc", pc)
        vex = state.block(opt_level=0).vex
        emu.state = old_state
        # Vex only allows indirect jumps as default block exits.
        # We can look at the default jumpkind for this block
        # to tell us

        if vex.jumpkind == "Ijk_Ret":
            log.debug("Caused by an unbounded return.")
            return "return"
        elif vex.jumpkind == "Ijk_Call":
            log.debug("Caused by an unbounded indirect function call.")
            return "call"
        elif vex.jumpkind in ("Ijk_Boring", "Ijk_Privileged", "Ijk_Yield"):
            log.debug("Caused by an unbounded indirect jump.")
            return "jump"
        else:
            log.error(f"Unexpected cause: {vex.jumpkind}")
            return "unknown"

    def _diagnose_unconstrained(
        self, emu: emulators.AngrEmulator, state: angr.SimState, pc: int
    ) -> HaltUnconstrained:
        target = state._ip

        target_str = self._get_target_type(emu, state, pc)

        log.debug(f"Jump target expression: {target}")
        expr = self._diagnose_expression(emu, target)

        return HaltUnconstrained(target=target_str, expr=expr)

    def _diagnose_deadended(
        self,
        emu: emulators.AngrEmulator,
        state: angr.SimState,
        pc: int,
        real: bool = True,
    ):
        expr = state._ip
        ip = emu.state.solver.eval_one(expr)
        kind: str

        if not emu.state.scratch.memory_map.contains_value(ip):
            log.debug(f"Execution entered unmapped memory at {ip:x} ({expr})")
            kind = "unmapped"
        elif (
            not emu.state.scratch.bounds.is_empty()
            and not emu.state.scratch.bounds.contains_value(ip)
        ):
            log.debug(f"Execution went out of bounds at {ip:x}")
            kind = "bounds"
        elif ip in emu.state.scratch.exit_points:
            log.debug(f"Execution hit an exit point at {ip:x}")
            kind = "exitpoint"
        elif real:
            log.debug(f"No clear cause for deadended state at {ip:x}")
            kind = "unknown"
        else:
            return HaltNoHalt(pc=ip)

        # Determine the target type
        target = self._get_target_type(emu, state, pc)

        # Determine full target expression
        expr = self._diagnose_expression(emu, expr)

        return HaltDeadended(kind=kind, target=target, pc=ip, expr=expr)

    def _diagnose_stop(self, emu: emulators.AngrEmulator, pc: int) -> Halt:
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
            log.debug(f"Stopped due to unbound PC after {pc:x}")
            (state,) = emu.mgr.unconstrained
            return self._diagnose_unconstrained(emu, state, pc)

        elif len(emu.mgr.deadended) > 0:
            # Single deadended state
            log.debug(f"Stopped due to execution limits after {pc:x}")
            (state,) = emu.mgr.deadended
            return self._diagnose_deadended(emu, state, pc)

        elif len(emu.mgr.active) > 1:
            # Divergent state.
            log.debug(f"State diverged after {pc:x}")

            state1, state2 = emu.mgr.active

            # SmallWorld aborts before categorizing divergent states.
            # These may not only diverge unexpectedly,
            # but may lead to deadended or unconstrained states.
            if state1._ip.symbolic:
                log.debug("State at {state1._ip} is unconstrained")
                halt1 = self._diagnose_unconstrained(emu, state1, pc)
            else:
                halt1 = self._diagnose_deadended(emu, state1, pc, real=False)

            if state2._ip.symbolic:
                log.debug("State at {state2._ip} is unconstrained")
                halt2 = self._diagnose_unconstrained(emu, state2, pc)
            else:
                halt2 = self._diagnose_deadended(emu, state2, pc, real=False)

            log.debug(f"Guard for {state1._ip}: {state1.scratch.guard}")
            guard1 = self._diagnose_expression(emu, state1.scratch.guard)
            log.debug(f"Guard for {state2._ip}: {state2.scratch.guard}")
            guard2 = self._diagnose_expression(emu, state2.scratch.guard)

            return HaltDiverged(halt1, halt2, guard1, guard2)

        raise Exception("No cause for the emulator to halt")

    def _diagnose_oob(
        self, emu: emulators.AngrEmulator, crash: CrashResults
    ) -> DiagnosisOOB:
        try:
            emu.step()
            # Didn't trigger.  I wonder why.
            log.debug(
                f"Expected emulation to stop at {crash.trace[-1]:x}, but it didn't."
            )
            return DiagnosisOOBUnconfirmed()
        except exceptions.EmulationStop:
            pass

        # Handle it the same way, just with expected stops.
        halt = self._diagnose_stop(emu, crash.trace[-1])
        return DiagnosisOOBConfirmed(halt=halt)

    def _diagnose_illegal(self, emu: emulators.AngrEmulator, pc: int) -> IllegalInstr:
        block = emu.state.block(opt_level=0, strict_block_end=True)

        disas = block.disassembly
        if disas is not None and len(disas.insns) > 0:
            insn = disas.insns[0]
        else:
            insn = None

        if block.vex.jumpkind == "Ijk_NoDecode":
            if insn is not None:
                log.debug(f"Instruction at {pc:x} is illegal: {insn}")
                return IllegalInstrConfirmed(instr=str(insn))
            else:
                insn_mem = emu.read_memory_symbolic(pc, 16)
                log.debug(f"Instruction at {pc:x} is untranslatable: {insn_mem}")
                return IllegalInstrNoDecode(mem=repr(insn_mem))
        else:
            log.debug(f"Instruction at {pc:x} appears fine to vex: {insn}")
            log.debug(
                "vex may not be fully accurate.  Please consult relevant ISA docs to confirm."
            )
            return IllegalInstrUnconfirmed(instr=str(insn))

    def _diagnose_trap(self, emu: emulators.AngrEmulator, crash: CrashResults):
        block = emu.state.block(opt_level=0, strict_block_end=True)

        disas = block.disassembly
        if disas is not None and len(disas.insns) > 0:
            insn = disas.insns[0]
        else:
            insn = None

        if insn is not None:
            log.debug(f"Unicorn reported a trap at {insn}")
            log.debug("It's extremely unlikely angr will capture this behavior.")
        else:
            log.debug(
                f"Unicorn reported a trap at {crash.trace[-1]:x}; instruction is undecodable."
            )

        return DiagnosisTrap()

    def _diagnose_mem(
        self, emu: emulators.AngrEmulator, crash: CrashResults
    ) -> DiagnosisMemory:
        pc = crash.trace[-1]
        is_hook: bool = False
        safe_operands: typing.Dict[typing.Any, typing.Tuple[Expression, int]] = dict()
        unmapped_operands: typing.Dict[
            typing.Any, typing.Tuple[Expression, int]
        ] = dict()
        unsat_operands: typing.Dict[typing.Any, Expression] = dict()
        unconstrained_operands: typing.Dict[typing.Any, Expression] = dict()

        if crash.mem_operands is None:
            # This is almost certainly a memory error triggered by a model.
            log.debug(f"Memory error at {pc:x} has no associated cause.")
            is_hook = True
        else:
            for operand, _ in crash.mem_operands:
                log.debug(f"Operand: {operand}")
                expr = operand.symbolic_address(emu)
                res = self._diagnose_expression(emu, expr)
                if expr.symbolic:
                    try:
                        (value,) = emu.state.solver.eval_atmost(expr, 1)
                    except angr.errors.SimUnsatError:
                        # No possible values for this expression
                        unsat_operands[operand] = res
                        continue
                    except angr.errors.SimValueError:
                        # Value is unconstrained
                        unconstrained_operands[operand] = res
                        continue
                else:
                    value = expr.concrete_value

                if emu.state.scratch.memory_map.contains_value(value):
                    safe_operands[operand] = (res, value)
                else:
                    unmapped_operands[operand] = (res, value)

        return DiagnosisMemory(
            is_hook=is_hook,
            safe_operands=safe_operands,
            unmapped_operands=unmapped_operands,
            unconstrained_operands=unconstrained_operands,
            unsat_operands=unsat_operands,
        )

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
        elif crash.cause is CrashCause.MEM_READ:
            return TriageMemory(
                message="Crash caused by memory read error",
                access=MemoryAccess.READ,
                trace=crash.trace,
                diagnosis=diagnosis,
            )
        elif crash.cause is CrashCause.MEM_WRITE:
            return TriageMemory(
                message="Crash caused by memory read error",
                access=MemoryAccess.WRITE,
                trace=crash.trace,
                diagnosis=diagnosis,
            )
        elif crash.cause is CrashCause.MEM_FETCH:
            return TriageMemory(
                message="Crash caused by memory read error",
                access=MemoryAccess.FETCH,
                trace=crash.trace,
                diagnosis=diagnosis,
            )
        else:
            raise exceptions.AnalysisError(f"Unexpected crash cause {crash.cause}")

    def _diagnose(self, machine: state.Machine, crash: CrashResults):
        # Set up an angr emulator
        def angr_init(emu):
            emu.state.memory.read_strategies = [SimConcretizationStrategyFault(True)]
            emu.state.memory.write_strategies = [SimConcretizationStrategyFault(False)]

        emu = emulators.AngrEmulator(machine.get_platform(), init=angr_init)
        emu.enable_linear()
        machine.apply(emu)
        emu.initialize()

        diagnosis_early: typing.Optional[DiagnosisEarly]

        # Step through the emulator so I can tell if we're following the trace.
        for i in range(0, len(crash.trace) - 1):
            diagnosis_early = self._check_trace(i, crash.trace, emu)
            if diagnosis_early is not None:
                hint = self._get_early_hint(crash, diagnosis_early)
                self.hinter.send(hint)
                return

            try:
                emu.step()
            except UnboundAddressError as e:
                # Emulator tried to concretize an unbound address
                address = self._diagnose_expression(emu, e.address)
                access = MemoryAccess.READ if e.is_read else MemoryAccess.WRITE
                diagnosis_early = DiagnosisEarlyMemory(
                    index=i, access=access, address=address
                )
                hint = self._get_early_hint(crash, diagnosis_early)

                self.hinter.send(hint)
                return
            except exceptions.EmulationStop:
                # Emulator stopped early.
                log.debug(f"Unexpected stop after {crash.trace[i]:x}")

                halt = self._diagnose_stop(emu, crash.trace[i])
                diagnosis_early = DiagnosisEarlyHalt(index=i, halt=halt)
                hint = self._get_early_hint(crash, diagnosis_early)

                self.hinter.send(hint)
                return
            except exceptions.EmulationExecInvalidFailure:
                # Emulator encountered an unexpected illegal instruction.
                # Unicorn and angr have different ISA coverage,
                # so this isn't expected.
                log.debug(f"Unexpected illegal instruction at {crash.trace[i]:x}")

                illegal = self._diagnose_illegal(emu, crash.trace[i])
                diagnosis_early = DiagnosisEarlyIllegal(index=i, illegal=illegal)
                hint = self._get_early_hint(crash, diagnosis_early)

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
            diagnosis_oob = self._diagnose_oob(emu, crash)
            hint = TriageOOB(
                message="Crash caused by out of bounds execution",
                trace=crash.trace,
                diagnosis=diagnosis_oob,
            )
        elif crash.cause is CrashCause.ILLEGAL:
            illegal = self._diagnose_illegal(emu, crash.trace[-1])
            diagnosis_illegal = DiagnosisIllegal(illegal=illegal)
            hint = TriageIllegal(
                message="Crash caused by illegal instruction",
                trace=crash.trace,
                diagnosis=diagnosis_illegal,
            )
        elif crash.cause is CrashCause.TRAP:
            diagnosis_trap = self._diagnose_trap(emu, crash)
            hint = TriageTrap(
                message="Crash caused by unhandled trap",
                trace=crash.trace,
                diagnosis=diagnosis_trap,
            )
        elif crash.cause is CrashCause.MEM_READ:
            diagnosis_mem = self._diagnose_mem(emu, crash)
            hint = TriageMemory(
                message="Crash caused by read error",
                access=MemoryAccess.READ,
                trace=crash.trace,
                diagnosis=diagnosis_mem,
            )
        elif crash.cause is CrashCause.MEM_WRITE:
            diagnosis_mem = self._diagnose_mem(emu, crash)
            hint = TriageMemory(
                message="Crash caused by read error",
                access=MemoryAccess.WRITE,
                trace=crash.trace,
                diagnosis=diagnosis_mem,
            )
        elif crash.cause is CrashCause.MEM_FETCH:
            diagnosis_mem = self._diagnose_mem(emu, crash)
            hint = TriageMemory(
                message="Crash caused by read error",
                access=MemoryAccess.FETCH,
                trace=crash.trace,
                diagnosis=diagnosis_mem,
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
