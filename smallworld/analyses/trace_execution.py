import copy
import hashlib
import logging
import typing
from enum import Enum

import capstone

import smallworld
from smallworld.analyses.trace_execution_types import CmpInfo, TraceElement, TraceRes
from smallworld.instructions import RegisterOperand

from .. import platforms
from ..hinting.hints import TraceExecutionHint
from . import analysis

logger = logging.getLogger(__name__)


class TraceExecutionCBPoint(Enum):
    BEFORE_INSTRUCTION = 1
    AFTER_INSTRUCTION = 2


def get_cmp_info(
    platform: smallworld.platforms.Platform,
    emulator: smallworld.emulators.Emulator,
    cs_insn: capstone.CsInsn,
) -> typing.Tuple[typing.List[CmpInfo], typing.List[int]]:
    pdefs = platforms.defs.PlatformDef.for_platform(platform)
    if cs_insn.mnemonic in pdefs.compare_mnemonics:
        # it's a compare -- return list of "reads'
        sw_insn = smallworld.instructions.Instruction.from_capstone(cs_insn)
        cmp_info = []
        for op in cs_insn.operands:
            if op.type == capstone.CS_OP_MEM and (op.access & capstone.CS_AC_READ):
                cmp_info.append(sw_insn._memory_reference_operand(op))
            if op.type == capstone.CS_OP_REG and (op.access & capstone.CS_AC_READ):
                cmp_info.append(RegisterOperand(cs_insn.reg_name(op.value.reg)))
            if op.type == capstone.CS_OP_IMM:
                cmp_info.append(op.value.imm)
        immediates = []
        for op in cs_insn.operands:
            if op.type == capstone.x86.X86_OP_IMM:
                immediates.append(op.value.imm)
        return (cmp_info, immediates)
    return ([], [])


class TraceExecution(analysis.Analysis):
    name = "trace_execution"
    description = "perform one concrete execution given a machine state, collecting trace, coverage, and errors"
    version = "0.0.1"

    def __init__(
        self,
        *args,
        num_insns: int,
        seed: int = 1234567,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.num_insns = num_insns
        self.seed = seed
        self.before_instruction_cbs: typing.List[typing.Any] = []
        self.after_instruction_cbs: typing.List[typing.Any] = []

    def register_emu_summary(self):
        pdefs = platforms.defs.PlatformDef.for_platform(self.platform)
        m = hashlib.md5()
        for reg in pdefs.general_purpose_registers:
            vs = (str(self.emulator.read_register(reg))).encode("utf-8")
            m.update(vs)
        return m.hexdigest()

    def register_cb(self, cb_point, cb_function):
        assert isinstance(cb_point, TraceExecutionCBPoint)
        if cb_point == TraceExecutionCBPoint.BEFORE_INSTRUCTION:
            self.before_instruction_cbs.append(cb_function)
        if cb_point == TraceExecutionCBPoint.AFTER_INSTRUCTION:
            self.after_instruction_cbs.append(cb_function)

    def run(self, machine: smallworld.state.Machine) -> None:
        self.machine = copy.deepcopy(machine)
        self.platform = machine.get_platform()
        self.emulator = smallworld.emulators.unicorn.UnicornEmulator(self.platform)
        self.machine.apply(self.emulator)

        logger.debug(f"starting regs in emu {self.register_emu_summary()}")

        def get_insn(pc):
            code = self.emulator.read_memory(pc, 15)
            if code is None:
                raise smallworld.exceptions.AnalysisRunError(
                    "Unable to read next instruction out of emulator memory"
                )
            cs_insns, disas = self.emulator._disassemble(code, pc, 1)
            return cs_insns[0]

        the_exc = None
        emu_result = TraceRes.ER_NONE

        pdefs = platforms.defs.PlatformDef.for_platform(self.platform)

        i = 0
        trace = []
        while True:
            pc = self.emulator.read_register("pc")
            # happens that pc may have been set to a value out of
            # bounds by prev instruction.  If so, we'll get here and
            # should detect that.
            if (
                not self.emulator._bounds.is_empty()
                and not self.emulator._bounds.contains_value(pc)
            ):
                emu_result = TraceRes.ER_BOUNDS
                break
            cs_insn = get_insn(pc)
            cmp_info, imm_info = get_cmp_info(self.platform, self.emulator, cs_insn)
            branch_info = cs_insn.mnemonic in pdefs.conditional_branch_mnemonics
            te = TraceElement(
                pc, i, cs_insn.mnemonic, cs_insn.op_str, cmp_info, branch_info, imm_info
            )
            trace.append(te)
            # run any callbacks
            for before_cb in self.before_instruction_cbs:
                before_cb(self.emulator, pc, te)
            try:
                i += 1
                logger.debug(cs_insn)
                self.emulator.step()
            except (
                smallworld.exceptions.EmulationBounds,
                smallworld.exceptions.EmulationExitpoint,
            ):
                # this one really isnt an error of any kind; we
                # encountered code we were not supposed to execute
                emu_result = TraceRes.ER_BOUNDS
                break
            except Exception as e:
                # grab the exception and save it for hinting
                emu_result = TraceRes.ER_FAIL
                the_exc = e
                break
            # run any after callbacks
            for after_cb in self.after_instruction_cbs:
                after_cb(self.emulator, pc, te)
            if i == self.num_insns:
                emu_result = TraceRes.ER_MAX_INSNS
                break

        m = hashlib.md5()
        for te in trace:
            logger.debug(te)
            m.update((str(te.pc).encode("utf-8")))

        logger.info(
            f"captured trace of {i} instructions, res={emu_result} trace_digest={m.hexdigest()}"
        )

        assert emu_result is not None

        hint = TraceExecutionHint(
            message="A single execution trace",
            trace=trace,
            trace_digest=m.hexdigest(),
            seed=self.seed,
            emu_result=emu_result,
            exception=the_exc,
            exception_class=str(type(the_exc)),
        )

        self.hinter.send(hint)
