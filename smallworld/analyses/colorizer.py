import copy
import logging
import random
import struct
import typing

import capstone

from .. import hinting, platforms, state
from ..exceptions import AnalysisRunError  # , EmulationBounds
from ..instructions import (
    BSIDMemoryReferenceOperand,
    Instruction,
    Operand,
    RegisterOperand,
)
from . import analysis
from .trace_execution import TraceExecution, TraceExecutionCBPoint

logger = logging.getLogger(__name__)

MIN_ACCEPTABLE_COLOR_INT = 0x20
BAD_COLOR = (2**64) - 1

Colors = typing.Dict[int, typing.Tuple[Operand, int, int, Instruction, int]]

Shad = typing.Dict[int, typing.Tuple[int, bool, int]]


class Colorizer(analysis.Analysis):
    """
    A simple kind of data flow analysis via tracking distinct values
    (colors) and employing instruction use/def analysis

    We run multiple micro-executions of the code starting from same
    entry. At the start of each, we randomize register values that
    have not already been initialized. We maintain a "colors" map from
    dynamic values to when/where we first observed them. This map is
    initially empty. Before emulating an instruction, we examine the
    values (registers and memory) it will read. If any are not in the
    colors map, that is the initial sighting of that value and we emit
    a hint to that effect and add a color to the map. If any color is
    already in the map, then that is a def-use flow from the time or
    place at which that value was first observed to this instruction.
    Similarly, after emulating an instruction, we examine every value
    written to a register or memory. If a value is not in the colors
    map, it is a new, computed result and we hint about its creation
    and add it to the map. If it is in the colors map, we do nothing
    since it just a copy.

    Whilst looking at reads and writes for instructions, we hint if any
    correspond to unavailable memory.

    Arguments:
        num_micro_executions: The number of micro-executions to run.
        num_insns: The number of instructions to micro-execute.
        seed: Random seed for test stability, or None.

    """

    name = "colorizer"
    description = "it's almost taint"
    version = "0.0.1"

    def __init__(
        self,
        *args,
        num_micro_executions: int = 10,
        num_insns: int = 200,
        seed: int = 99,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        # Create our own random so we can avoid contention.
        self.random = random.Random()
        self.seed = seed

        self.num_micro_executions = num_micro_executions
        self.num_insns = num_insns
        self.colors: Colors = {}
        self.shadow_register: typing.Dict[str, Shad] = {}
        self.shadow_memory: Shad = {}
        # self.edge: typing.Dict[int, typing.Dict[int, typing.Tuple[str, int, int]]] = {}

    def _get_instr_at_pc(self, emu, pc: int) -> capstone.CsInsn:
        code = emu.read_memory(pc, 15)  # longest possible instruction
        if code is None:
            raise AnalysisRunError(
                "Unable to read next instruction out of emulator memory"
            )
        (insns, disas) = emu._disassemble(code, pc, 2)
        insn = insns[0]
        return insn

    def _operand_size(self, operand: Operand) -> int:
        if type(operand) is RegisterOperand:
            # return size of a reg based on its name
            return self.pdef.registers[operand.name].size
        elif type(operand) is BSIDMemoryReferenceOperand:
            # memory operand knows its size
            return operand.size
        return 0

    def run(self, machine: state.Machine) -> None:
        # collect hints for each microexecution, in a list of lists

        self.orig_machine = copy.deepcopy(machine)
        self.orig_cpu = self.orig_machine.get_cpu()
        self.platform = self.orig_cpu.platform
        self.pdef = platforms.PlatformDef.for_platform(self.platform)
        self.random.seed(self.seed)

        # start off by collecting micro execution traces
        logger.info("Collecting micro-execution traces")
        patch = []
        for i in range(self.num_micro_executions):
            logger.info("-------------------------")
            logger.info(f"Gathering trace for micro exec {i}")

            traceA = TraceExecution(self.num_insns, True, self.seed + i)
            traceA.run(machine)
            patch.append(traceA.get_patch())

        def check_rws(emu, pc, te, is_read):
            logger.info(te)
            cs_insn = self._get_instr_at_pc(emu, pc)
            sw_insn = Instruction.from_capstone(cs_insn)
            if is_read:
                operand_list = sw_insn.reads
                lab = "read"
            else:
                operand_list = sw_insn.writes
                lab = "write"
            rws = []
            for operand in operand_list:
                logger.debug(f"pc={pc:x} {lab}_operand={operand}")
                if type(operand) is RegisterOperand and operand.name == "rflags":
                    continue
                sz = self._operand_size(operand)
                # print(f"operand={operand} sz={sz}")
                if type(operand) is BSIDMemoryReferenceOperand:
                    # if addr not mapped, discard this operand
                    a = operand.address(emu)
                    ar = (a, a + sz)
                    if not emu._is_address_range_mapped(ar):
                        continue
                conc = operand.concretize(emu)
                color = self._concrete_val_to_color(conc, sz)
                tup = (operand, conc, color, sz)
                rws.append(tup)
            rws.sort(key=lambda e: e[0].__repr__())
            if len(rws) == 0:
                return
            for rw in rws:
                (operand, conc, color, sz) = rw
                if color == BAD_COLOR:
                    pass
                else:
                    self._check_color(
                        emu, is_read, rw, sw_insn, self.micro_exec_num, te.ic
                    )
                # self.update_shadow(emu, pc, is_read, rw)
            if is_read:
                self.reads = rws

        def before_instruction_cb(emu, pc, te):
            check_rws(emu, pc, te, True)

        def after_instruction_cb(emu, pc, te):
            check_rws(emu, pc, te, False)

        logger.info("re-running traces with colorizer")
        # now follow those same traces tracking colors
        for self.micro_exec_num in range(self.num_micro_executions):
            logger.info("-------------------------")
            logger.info(
                f"Running colorizer on trace for micro exec {self.micro_exec_num}"
            )
            self.colors = {}
            self.shadow_register = {}
            self.shadow_memory = {}
            # self.edge = {}
            traceA = TraceExecution(
                self.num_insns, True, self.seed + self.micro_exec_num
            )
            traceA.register_cb(
                TraceExecutionCBPoint.BEFORE_INSTRUCTION, before_instruction_cb
            )
            traceA.register_cb(
                TraceExecutionCBPoint.AFTER_INSTRUCTION, after_instruction_cb
            )
            traceA.run(machine, patch[self.micro_exec_num])

            # NOTE: Please keep this code
            # if False:
            #     print("digraph{")
            #     print(" rankdir=LR")
            #     pc2nodeid = {}
            #     nodeid2pc = {}
            #     nodeids = set([])

            #     def add_pc(pc):
            #         if pc not in pc2nodeid:
            #             nodeid = f"node_{len(nodeids)}"
            #             nodeids.add(nodeid)
            #             pc2nodeid[pc] = nodeid
            #             nodeid2pc[nodeid] = pc

            #     for pc1 in self.edge.keys():
            #         add_pc(pc1)
            #         for pc2 in self.edge[pc1].keys():
            #             add_pc(pc2)
            #     for nodeid in nodeids:
            #         print(f'{nodeid} [label="0x{nodeid2pc[nodeid]:x}"]')
            #     for pc1 in self.edge.keys():
            #         for pc2 in self.edge[pc1].keys():
            #             (lab, conc, color) = self.edge[pc1][pc2]
            #             n1 = pc2nodeid[pc1]
            #             n2 = pc2nodeid[pc2]
            #             print(f'{n1} -> {n2} [label="{lab}"]')
            #     print("}")

    def _concrete_val_to_color(
        self, concrete_value: typing.Union[int, bytes, bytearray], size: int
    ) -> int:
        # this concrete value can be an int (if it came from a register)
        # or bytes (if it came from memory read)
        # we want these in a common format so that we can see them as colors
        the_bytes: bytes = b""
        if type(concrete_value) is int:
            if concrete_value < MIN_ACCEPTABLE_COLOR_INT:
                return BAD_COLOR
            the_bytes = concrete_value.to_bytes(size, byteorder="little")
        elif (type(concrete_value) is bytes) or (type(concrete_value) is bytearray):
            # assuming little-endian
            if (
                int.from_bytes(concrete_value, byteorder="little")
                < MIN_ACCEPTABLE_COLOR_INT
            ):
                return BAD_COLOR
            the_bytes = concrete_value
        else:
            assert 1 == 0
        # let's make color a number
        if size == 8:
            return struct.unpack("<Q", the_bytes)[0]
        if size == 4:
            return struct.unpack("<L", the_bytes)[0]
        if size == 2:
            return struct.unpack("<H", the_bytes)[0]
        assert size == 1
        return struct.unpack("<B", the_bytes)[0]

    def _add_color(
        self,
        color: int,
        operand: Operand,
        insn: Instruction,
        exec_num: int,
        insn_num: int,
    ) -> None:
        self.colors[color] = (operand, exec_num, insn_num, insn, 1 + len(self.colors))

    def _check_color(
        self,
        emu,
        is_read: bool,
        rw,  #: typing.Union[Operand, int, int],
        # reads: typing.List[typing.Tuple[Operand, int, int]],
        insn: Instruction,
        exec_num: int,
        insn_num: int,
    ):
        (operand, conc, color, operand_size) = rw
        if color in self.colors.keys():
            # previously observed color
            if is_read:
                # read-flow: use of a previously recorded color value
                msg = "read-flow"
            else:
                # write of a previously seen value
                # ... its just a copy so no hint, right?
                msg = "write-copy"
            hint = self._dynamic_value_hint(
                emu,
                operand,
                operand_size,
                color,
                insn,
                is_read,
                False,
                exec_num,
                insn_num,
                msg,
            )
            self.hinter.send(hint)
        else:
            # new color
            self._add_color(color, operand, insn, exec_num, insn_num)
            if is_read:
                # read-def: use of a NOT previously recorded color value. As
                # long as the value is something reasonable, we'll record it as
                # a new color
                msg = "read-def"
            else:
                msg = "write-def"
            hint = self._dynamic_value_hint(
                emu,
                operand,
                operand_size,
                color,
                insn,
                is_read,
                True,
                exec_num,
                insn_num,
                msg,
            )
            self.hinter.send(hint)

    def _dynamic_value_hint(
        self,
        emu,
        operand: Operand,
        size: int,
        color: int,
        insn: Instruction,
        is_use: bool,
        is_new: bool,
        exec_num: int,
        insn_num: int,
        message: str,
    ):
        pc = insn.address
        if type(operand) is RegisterOperand:
            return hinting.DynamicRegisterValueHint(
                reg_name=operand.name,
                size=size,
                color=color,
                dynamic_value=color,
                use=is_use,
                new=is_new,
                pc=pc,
                micro_exec_num=exec_num,
                instruction_num=insn_num,
                message=message,
            )
        elif type(operand) is BSIDMemoryReferenceOperand:
            base_name = "None"
            if operand.base is not None:
                base_name = operand.base
            index_name = "None"
            if operand.index is not None:
                index_name = operand.index
            return hinting.DynamicMemoryValueHint(
                address=operand.address(emu),
                base=base_name,
                index=index_name,
                scale=operand.scale,
                offset=operand.offset,
                color=color,
                dynamic_value=color,
                size=operand.size,
                use=is_use,
                new=is_new,
                pc=pc,
                micro_exec_num=exec_num,
                instruction_num=insn_num,
                message=message,
            )
        else:
            assert 1 == 0

    # def update_shadow(self, emu, pc, is_read, rw):
    #     (operand, conc, color, operand_size) = rw

    #     if type(operand) is RegisterOperand:
    #         r = self.pdef.registers[operand.name]
    #         if type(r) is platforms.RegisterAliasDef:
    #             base_reg = r.parent
    #             start = r.offset
    #         else:
    #             base_reg = r.name
    #             start = 0
    #         if base_reg not in self.shadow_register:
    #             self.shadow_register[base_reg] = {}
    #         shad = self.shadow_register[base_reg]
    #         end = start + r.size
    #         lab = f"reg({r.name})"
    #     else:
    #         start = operand.address(emu)
    #         shad = self.shadow_memory
    #         end = start + operand.size
    #         lab = f"mem({start:x},{operand.size})"

    #     if is_read:
    #         # read. check labels on things we are reading to deduce flows
    #         fs = set([])
    #         for o in range(start, end):
    #             if o in shad:
    #                 (pc_from, is_read, conc_from) = shad[o]
    #                 if is_read:
    #                     f = f"{lab} r->r"
    #                 else:
    #                     f = f"{lab} w->r"
    #                 f += f" flow from pc={pc_from:x} to pc={pc:x} conc={conc} conc_from={conc_from} color={color}"
    #                 if f not in fs:
    #                     logger.info(f)
    #                     if pc_from not in self.edge:
    #                         self.edge[pc_from] = {}
    #                     if pc not in self.edge[pc_from]:
    #                         self.edge[pc_from][pc] = (lab, conc, color)
    #                     # self.edge.add((pc_from, lab, pc, conc, color))
    #                 fs.add(f)
    #     else:
    #         # write. we are overwriting things so no reason to check on bytes before doing so
    #         for o in range(start, end):
    #             shad[o] = (pc, is_read, conc)
