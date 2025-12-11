import copy
import hashlib
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


MIN_ACCEPTABLE_COLOR_INT = 0x80
BAD_COLOR = (2**64) - 1

Colors = typing.Dict[int, typing.Tuple[Operand, int, Instruction, int]]

Shad = typing.Dict[int, typing.Tuple[int, bool, int]]


def randomize_uninitialized(
    machine: state.Machine,
    seed: int = 123456,
    extra_regs: typing.List[str] = [],
    bss_start: typing.Optional[int] = None,
    bss_size: typing.Optional[int] = None,
) -> state.Machine:
    """Consider all parts of the machine that can be written to (registers
    + memory regions). Write random values to any bytes in those machine
       parts which are currently uninitialized. So this only works if we
    have a way to tell if registers or memory have not been initialized.

    Randomize all general purpose regs (plus regs in list of
    extra_regs arg) that have not already been set.  Also, for any
    Heap, Stack, RawMemory or Memory regions, randomize any bytes that
    have not been set. This last part is to come since we don't
    currently have a way to tell which parts of memory have been
    written and which parts have not. Further, there are kinds of
    memory (Stack) which currently will break if we randomize all
    bytes.

    Note that, for a register, it is either set or not.  We can't tell
    if, say edx part of rdx has been set.

    NOTE: If we want a seed to determine the specific random values
    chosen for regs and mem bytes, then we need to arrange for any
    iterators over things to do so in a repeatable way.  For instance,
    we need to get register names and sort them then randomize them in
    that order.  Similarly, we do things to make sure we are
    randomizing memory objects or the segments within them in same
    order every time.


    """

    random.seed(seed)

    m = hashlib.md5()
    platform = machine.get_platform()
    machine_copy = copy.deepcopy(machine)

    pdefs = platforms.defs.PlatformDef.for_platform(platform)

    def get_reg(machine, reg_name):
        cpu = machine.get_cpu()
        for x in cpu:
            if isinstance(x, state.Register):
                if x.name == reg_name:
                    return x
        return None

    reg_names = list(pdefs.registers.keys())
    reg_names.sort()
    for name in reg_names:
        if (name in pdefs.general_purpose_registers) or (name in extra_regs):
            reg = get_reg(machine_copy, name)
            if reg.get_content() is None:
                # this means reg is uninitialized; ok to randomize
                v = random.randint(0, (1 << (8 * reg.size)) - 1)
                reg.set(v)
                m.update(str(v).encode("utf-8"))
                logger.debug(f"randomize_unitialized: reg{name} randomized to {v:x}")

    mems = {}
    memsk = []
    for mem in machine_copy:
        if isinstance(mem, state.memory.Memory):
            mems[str(mem)] = mem
            memsk.append(str(mem))
    memsk.sort()

    for mk in memsk:
        mem = mems[mk]

        def randomize_mem(mem, start, size):
            bytz = random.randbytes(size)
            mem.write_bytes(start, bytz)
            m.update(bytz)

        if isinstance(mem, state.memory.code.Executable):
            # nothing to randomize here except maybe bss
            if (bss_start is not None) and (bss_size is not None):
                # see above about reg_names; same deal
                segstarts = []
                for seg_start, bv in mem.items():
                    segstarts.append(seg_start)
                segstarts.sort()
                for seg_start in segstarts:
                    bv = mem[seg_start]
                    seg_end = seg_start + bv.get_size()
                    logger.debug(f"bss_start={bss_start:x} seg_start={seg_start:x}")
                    logger.debug(
                        f"bss_end={bss_start + bss_size:x} seg_end={seg_end:x}"
                    )
                    if (bss_start >= seg_start) and (bss_start + bss_size <= seg_end):
                        logger.debug(
                            f"randomize_unitialized: bss in elf segment {seg_start:x}..{seg_end:x}. perturbing it."
                        )
                        randomize_mem(mem, mem.address + bss_start, bss_size)

        elif isinstance(mem, state.memory.Memory):
            mem_rngs: typing.List[typing.Any] = []
            for mem_rng in mem.get_ranges_uninitialized():
                mem_rngs.append(mem_rng)
            mem_rngs.sort()

            for mem_rng in mem_rngs:
                logger.debug(
                    f"randomize_unitialized: memory({mem}) type({type(mem)}) has uninitialized range {mem_rng}: perturbing it."
                )
                randomize_mem(mem, mem_rng.start, len(mem_rng))

    logger.info(f"seed={seed} digest of changes made to machine: {m.hexdigest()}")

    return machine_copy


class Colorizer(analysis.Analysis):
    """A simple kind of data flow analysis via tracking distinct values
    (colors) and employing instruction use/def analysis

    We run a single micro-execution of the code. Before any code is
    executed, we randomize register values that have not already been
    initialized. We maintain a "colors" map from dynamic values to
    when/where we first observed them. This map is initially
    empty. Before emulating an instruction, we examine the values
    (registers and memory) it will read. If any are not in the colors
    map, that is the initial sighting of that value and we emit a hint
    to that effect and add a color to the map. If any color is already
    in the map, then that is a def-use flow from the time or place at
    which that value was first observed to this instruction.
    Similarly, after emulating an instruction, we examine every value
    written to a register or memory. If a value is not in the colors
    map, it is a new, computed result and we hint about its creation
    and add it to the map. If it is in the colors map, we do nothing
    since it just a copy.

    Here are the kinds of hints output by this analysis

    DynamicRegisterValueHint
    -- about value in a register at a particular instruction in the trace

    DynamicMemoryValueHint
    -- about a value in memory at a particular instruction in the trace

    These can be "new" values if that is first time we have seen that
    color (dynamic value).  Or they can be not-new, meaning this is a
    use of that value previously observed, i.e. a data flow.

    They can also be reads or writes.

    Note: Yes, this kind of analysis depends upon colors being big-ish
    unique values. There is a constant up top indicating the minimum
    color value.


    Arguments:
        num_insns: The number of instructions to micro-execute.

    """

    name = "colorizer"
    description = "it's almost taint"
    version = "0.0.1"

    def __init__(
        self,
        *args,
        exec_id: int,
        num_insns: int = 200,
        debug: bool = False,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.exec_id = exec_id
        self.num_insns = num_insns
        self.colors: Colors = {}
        self.shadow_register: typing.Dict[str, Shad] = {}
        self.shadow_memory: Shad = {}
        self.debug = debug
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

    def htime(self):
        if not (hasattr(self, "time_mon")):
            self.time_mon = 1
        else:
            self.time_mon += 1
        return self.time_mon

    def run(self, machine: state.Machine) -> None:
        # collect hints for each microexecution, in a list of lists

        self.orig_machine = copy.deepcopy(machine)
        self.orig_cpu = self.orig_machine.get_cpu()
        self.platform = self.orig_cpu.platform
        self.pdef = platforms.PlatformDef.for_platform(self.platform)

        def check_rws(emu, pc, te, is_read):
            cs_insn = self._get_instr_at_pc(emu, pc)
            sw_insn = Instruction.from_capstone(cs_insn)
            # if pc == 0x21b1 and is_read:
            #     logger.info(f"pc={pc:x} before eax={emu.read_register('eax'):x} ecx={emu.read_register('ecx'):x}")
            #     breakpoint()
            if is_read:
                operand_list = sw_insn.reads
                # lab = "read"
            else:
                operand_list = sw_insn.writes
                # lab = "write"
            rws = []
            for operand in operand_list:
                # logger.debug(f"pc={pc:x} {lab}_operand={operand}")
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
                    self._check_color(emu, is_read, rw, sw_insn, te.ic)
                # self.update_shadow(emu, pc, is_read, rw)
            if is_read:
                self.reads = rws

        def before_instruction_cb(emu, pc, te):
            check_rws(emu, pc, te, True)

        def after_instruction_cb(emu, pc, te):
            check_rws(emu, pc, te, False)

        self.colors = {}
        self.shadow_register = {}
        self.shadow_memory = {}
        traceA = TraceExecution(self.hinter, num_insns=self.num_insns)
        traceA.register_cb(
            TraceExecutionCBPoint.BEFORE_INSTRUCTION, before_instruction_cb
        )
        traceA.register_cb(
            TraceExecutionCBPoint.AFTER_INSTRUCTION, after_instruction_cb
        )
        traceA.run(machine)

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
        # if size < 2:
        #     # let's please just have colors that are at least 2 bytes
        #     return BAD_COLOR
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
        insn_num: int,
    ) -> None:
        self.colors[color] = (operand, insn_num, insn, 1 + len(self.colors))

    def _check_color(
        self,
        emu,
        is_read: bool,
        rw,  #: typing.Union[Operand, int, int],
        insn: Instruction,
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
                insn_num,
                msg,
            )
            self.hinter.send(hint)
        else:
            # new color
            self._add_color(color, operand, insn, insn_num)
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
        insn_num: int,
        message: str,
    ):
        pc = insn.address
        if type(operand) is RegisterOperand:
            return hinting.DynamicRegisterValueHint(
                time=self.htime(),
                reg_name=operand.name,
                size=size,
                color=color,
                dynamic_value=color,
                use=is_use,
                new=is_new,
                pc=pc,
                instruction_num=insn_num,
                exec_id=self.exec_id,
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
                time=self.htime(),
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
                instruction_num=insn_num,
                exec_id=self.exec_id,
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
