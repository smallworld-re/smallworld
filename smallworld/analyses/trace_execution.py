import copy
import logging
import random
import typing
from dataclasses import dataclass
from enum import Enum

import capstone
import jsons

import smallworld

from .. import platforms
from . import analysis

# from ..emulators.unicorm import UnicornEmulator

logger = logging.getLogger(__name__)


class TraceExecutionCBPoint(Enum):
    BEFORE_INSTRUCTION = 1
    AFTER_INSTRUCTION = 2


CmpInfo = typing.Tuple[str, smallworld.instructions.Operand, int]


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
        for r in sw_insn.reads:
            label = None
            if isinstance(r, smallworld.instructions.BSIDMemoryReferenceOperand):
                label = "BSIDMemoryReference"
            elif isinstance(r, smallworld.instructions.RegisterOperand):
                label = "Register"
            assert label is not None
            tup = (label, r, r.concretize(emulator))
            cmp_info.append(tup)
        immediates = []
        for op in cs_insn.operands:
            if op.type == capstone.x86.X86_OP_IMM:
                immediates.append(op.value.imm)
        return (cmp_info, immediates)
    # smallworld/analyses/trace_execution.py:55: error: Incompatible return value type
    # (got      "tuple[list[tuple[str, Any, Any]], list[Any]]",
    #  expected "tuple[list[list[tuple[Operand | None, int]]], list[int]]")  [return-value]

    # its not a compare at all
    return ([], [])


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


@dataclass(frozen=True)
class TraceExecutionHint(smallworld.hinting.Hint):
    trace: typing.List[TraceElement]
    emu_result: TraceRes
    exception: typing.Optional[Exception]
    exception_class: str

    def to_dict(self):
        return {
            "trace": jsons.dump(self.trace),
            "emu_result": jsons.dump(self.emu_result),
            "exception": jsons.dump(self.exception),
            "exception_class": str(type(self.exception)),
        }

    @classmethod
    def from_dict(cls, dict):
        trace = jsons.load(dict, typing.List[TraceElement])
        emu_result = jsons.load(dict, TraceRes)
        exception = jsons.load(dict, Exception)
        return cls(trace, emu_result, exception)


class Patch:
    pass


@dataclass
class PatchRegister(Patch):
    name: str
    value: int


class TraceExecution(analysis.Analysis):
    name = "trace_execution"
    description = "perform one concrete execution given a machine state, collecting trace, coverage, and errors"
    version = "0.0.1"

    def __init__(
        self,
        *args,
        num_insns: int,
        randomize_regs: int = True,
        seed: int = 1234567,
        **kwargs,
    ):
        self.num_insns = num_insns
        self.randomize_regs = randomize_regs
        random.seed(seed)
        self.seed = seed
        # this will be used to record seq of changes to machine before
        # beginning emulation
        self.patch: typing.List[Patch] = []
        self.before_instruction_cbs: typing.List[typing.Any] = []
        self.after_instruction_cbs: typing.List[typing.Any] = []

    def randomize_registers(self) -> None:
        cpu = self.machine.get_cpu()
        regs = []
        pdefs = platforms.defs.PlatformDef.for_platform(self.platform)
        for reg in cpu:
            if (reg.name in pdefs.general_purpose_registers) and (
                reg.get_content() is None
            ):
                regs.append((reg.name, reg.size))
        regs.sort(key=lambda x: x[0])
        for name, size in regs:
            orig_val = self.emulator.read_register(name)
            new_val = 0
            bc = 0
            for i in range(0, size):
                new_val = new_val << 8
                if (
                    name in self.emulator.initialized_registers
                    and i in self.emulator.initialized_registers[name]
                ):
                    bs = 8 * (size - i - 1)
                    b = (orig_val >> bs) & 0xFF
                    # b = (orig_val >> (i * 8)) & 0xFF
                    new_val |= b
                else:
                    new_val |= random.randint(0, 255)
                    bc += 1
            if bc == 0:
                pass
            else:
                # make sure to update cpu as well as emu not sure why
                # print(f"reg {name} updated with {bc} random bytes to {new_val:x}")
                self.emulator.write_register(name, new_val)
                self.patch.append(PatchRegister(name, new_val))
                setattr(cpu, name, new_val)

    def get_patch(self) -> typing.List[Patch]:
        return self.patch

    def register_cb(self, cb_point, cb_function):
        assert isinstance(cb_point, TraceExecutionCBPoint)
        if cb_point == TraceExecutionCBPoint.BEFORE_INSTRUCTION:
            self.before_instruction_cbs.append(cb_function)
        if cb_point == TraceExecutionCBPoint.AFTER_INSTRUCTION:
            self.after_instruction_cbs.append(cb_function)

    def run(
        self,
        machine: smallworld.state.Machine,
        patch: typing.Union[None, typing.List[Patch]] = None,
    ) -> None:
        self.machine = copy.deepcopy(machine)
        self.platform = machine.get_platform()
        self.emulator = smallworld.emulators.unicorn.UnicornEmulator(self.platform)
        start_m = copy.deepcopy(self.machine)
        self.machine.apply(self.emulator)

        if patch is not None:
            # if there is a patch provided, that will specify edits to
            # machine before emulation
            for pr in patch:
                if isinstance(pr, PatchRegister):
                    self.emulator.write_register(pr.name, pr.value)
        else:
            # else, we will do something and record what we did in
            # case someone wants to get the patch
            if self.randomize_regs:
                self.randomize_registers()

        start_m.extract(self.emulator)

        def get_insn(pc):
            code = self.emulator.read_memory(pc, 15)
            if code is None:
                raise smallworld.exceptions.AnalysisRunError(
                    "Unable to read next instruction out of emulator memory"
                )
            (cs_insns, disas) = self.emulator._disassemble(code, pc, 1)
            return cs_insns[0]

        the_exc = None
        emu_result = TraceRes.ER_NONE

        pdefs = platforms.defs.PlatformDef.for_platform(self.platform)

        i = 0
        trace = []
        while True:
            pc = self.emulator.read_register("pc")
            cs_insn = get_insn(pc)
            # sw_insn = smallworld.instructions.Instruction.from_capstone(cs_insn)
            (cmp_info, imm_info) = get_cmp_info(self.platform, self.emulator, cs_insn)
            branch_info = cs_insn.mnemonic in pdefs.conditional_branch_mnemonics
            te = TraceElement(
                pc, i, cs_insn.mnemonic, cs_insn.op_str, cmp_info, branch_info, imm_info
            )
            trace.append(te)
            i += 1
            if i == self.num_insns:
                emu_result = TraceRes.ER_MAX_INSNS
                break
            # run any callbacks
            for before_cb in self.before_instruction_cbs:
                before_cb(self.emulator, pc, te)
            try:
                self.emulator.step()
            except smallworld.exceptions.EmulationBounds:
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

            logger.info("*** done with instr")

        assert emu_result is not None

        hint = TraceExecutionHint(
            message="A single execution trace",
            trace=trace,
            emu_result=emu_result,
            exception=the_exc,
            exception_class=str(type(the_exc)),
        )

        self.hinter.send(hint)
