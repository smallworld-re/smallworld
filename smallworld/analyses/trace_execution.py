import copy
import hashlib
import logging
import typing
from enum import Enum

import capstone

import smallworld
from smallworld.analyses.trace_execution_types import CmpEntry, TraceElement, TraceRes
from smallworld.instructions import BSIDMemoryReferenceOperand, RegisterOperand

from .. import platforms
from ..hinting.hints import TraceExecutionHint
from . import analysis

logger = logging.getLogger(__name__)


class TraceExecutionCBPoint(Enum):
    BEFORE_INSTRUCTION = 1
    AFTER_INSTRUCTION = 2


def _concrete_cmp_value(
    operand,
    emulator: smallworld.emulators.Emulator,
    byteorder: typing.Literal["little", "big"],
) -> typing.Optional[int]:
    """Concrete integer value of a cmp operand, read from the live emulator.

    A register operand yields its current value; a memory operand yields the
    integer loaded from its effective address (decoded with `byteorder`).
    Returns None if the value can't be read -- e.g. the memory operand's address
    is unmapped -- so a bad read degrades to "unknown" rather than aborting the
    trace.
    """
    try:
        v = operand.concretize(emulator)
    except Exception:
        return None
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        return int.from_bytes(v, byteorder)
    return int(v)


def get_cmp_info(
    platform: smallworld.platforms.Platform,
    emulator: smallworld.emulators.Emulator,
    cs_insn: capstone.CsInsn,
) -> typing.List[CmpEntry]:
    """What a comparison instruction compares: one CmpEntry per compared
    thing, each carrying the value observed at this point in the trace.

    Locations come from Instruction.reads, deduplicated and repr-sorted
    (test al, al reports al once; no lhs/rhs order is promised);
    immediates follow in decode order. Compare-and-branch instructions
    (compare_branch_mnemonics) are included, minus their final immediate
    -- the branch target. Empty means not a compare, or one whose use/def
    could not be interpreted (degrade, never abort the trace).
    """
    pdefs = platforms.defs.PlatformDef.for_platform(platform)
    is_compare = cs_insn.mnemonic in pdefs.compare_mnemonics
    is_compare_branch = cs_insn.mnemonic in pdefs.compare_branch_mnemonics
    if not (is_compare or is_compare_branch):
        return []
    try:
        # from_bytes with the caller's platform -- from_capstone selects by
        # capstone arch/mode, which is ambiguous across the ARM variants.
        # The expected ValueError is an ISA with no Instruction subclass;
        # anything else is a bug and propagates.
        sw_insn = smallworld.instructions.Instruction.from_bytes(
            bytes(cs_insn.bytes), cs_insn.address, platform
        )
        reads = sw_insn.reads
    except ValueError as exc:
        logger.info(f"get_cmp_info: no Instruction for {cs_insn.mnemonic}: {exc}")
        return []
    address_regs = set()
    for op in reads:
        if isinstance(op, BSIDMemoryReferenceOperand):
            for name in (op.base, op.index):
                if name is not None:
                    address_regs.add(name)
    # Compared locations: reads, minus non-value roles -- address-forming
    # registers (rbp in `cmp [rbp-0x1c], 47`) and the status register (a
    # plain ARM cmp reads the carry via the barrel shifter). KNOWN
    # IMPRECISION: `cmp rax, [rax]` reports only [rax] -- rax is both
    # pointer and compared value, and a read SET cannot say which.
    locations = sorted(
        (
            op
            for op in reads
            if isinstance(op, (RegisterOperand, BSIDMemoryReferenceOperand))
            and not (
                isinstance(op, RegisterOperand)
                and (op.name in address_regs or op.name == pdefs.status_register)
            )
        ),
        key=repr,
    )
    imm_ops = [op for op in cs_insn.operands if op.type == capstone.CS_OP_IMM]
    if is_compare_branch and imm_ops:
        imm_ops = imm_ops[:-1]  # drop the branch target

    byteorder: typing.Literal["little", "big"] = (
        "little" if pdefs.byteorder is platforms.Byteorder.LITTLE else "big"
    )
    return [
        CmpEntry(source=op, value=_concrete_cmp_value(op, emulator, byteorder))
        for op in locations
    ] + [CmpEntry(source=int(op.value.imm), value=int(op.value.imm)) for op in imm_ops]


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
            # capstone may decode zero instructions even though the bytes were
            # readable -- pc is in-bounds but points at something that is not a
            # valid instruction (data, or a placeholder/dispatch region such as
            # the libc-model area).  Signal that with None so the trace loop can
            # terminate cleanly instead of letting `cs_insns[0]` raise an
            # IndexError that escapes run() and aborts the caller.
            if not cs_insns:
                return None
            return cs_insns[0]

        the_exc: typing.Optional[Exception] = None
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
            if cs_insn is None:
                # In-bounds pc with no decodable instruction.  Treat it as an
                # emulation failure (control reached non-code) and stop, rather
                # than crashing the whole analysis.  Recorded like any faulting
                # step: ER_FAIL with a descriptive exception for hinting.
                emu_result = TraceRes.ER_FAIL
                the_exc = smallworld.exceptions.AnalysisRunError(
                    f"no decodable instruction at pc {pc:#x}"
                )
                break
            cmp_entries = get_cmp_info(self.platform, self.emulator, cs_insn)
            branch_info = cs_insn.mnemonic in pdefs.conditional_branch_mnemonics
            # TraceElement keeps its historical parallel-list shape (cmp /
            # immediates / index-aligned cmp_values): its pickled form and
            # its consumers (magrathea) depend on it. Derived here from the
            # self-contained entries; immediates are the int-sourced ones.
            te = TraceElement(
                pc,
                i,
                cs_insn.mnemonic,
                cs_insn.op_str,
                [e.source for e in cmp_entries],
                branch_info,
                [e.source for e in cmp_entries if isinstance(e.source, int)],
                [e.value for e in cmp_entries],
            )
            trace.append(te)
            # run any callbacks

            if pc not in self.emulator.function_hooks:
                for before_cb in self.before_instruction_cbs:
                    before_cb(self.emulator, pc, te)
            try:
                i += 1
                logger.debug(cs_insn)
                self.emulator.step()
            except smallworld.exceptions.EmulationExitpoint:
                # Reached a designated exit point (the harnessed function's
                # ret/end): a clean, intended completion. Kept distinct from
                # ER_BOUNDS so callers can tell "the function returned" from
                # "control escaped the allowed region."
                emu_result = TraceRes.ER_EXITPOINT
                break
            except smallworld.exceptions.EmulationBounds:
                # Execution left the allowed bounds without hitting an exit
                # point -- e.g. an indirect jump through a garbage pointer. Not
                # a hard emulation fault, but not a clean return either.
                emu_result = TraceRes.ER_BOUNDS
                break
            except Exception as e:
                # grab the exception and save it for hinting
                emu_result = TraceRes.ER_FAIL
                the_exc = e
                break
            # run any after callbacks
            if pc not in self.emulator.function_hooks:
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
