import copy
import hashlib
import logging
import random
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
    mem_addrs = []
    for mem in machine_copy:
        if isinstance(mem, state.memory.Memory):
            mem_addrs.append(mem.address)
            mems[mem.address] = mem
    mem_addrs.sort()

    for ma in mem_addrs:
        mem = mems[ma]

        def randomize_mem(mem, start, size):
            if size == 0:
                return
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
            mem_rngs.sort(key=lambda x: x.start)

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

    We run a single micro-execution of the code, given the input (to
    `run` method) machine state, single-stepping instructions and
    interposing for analysis before and after each instruction to
    check values dynamically read / written by each instruction.  We
    maintain a "colors" map from these dynamic values to when/where we
    first observed them. This map is initially empty. Before emulating
    an instruction, we examine the values (registers and memory) it
    will read. If any are not in the colors map, that is the initial
    sighting of that value and we emit a hint to that effect and add a
    color to the map. If any color is already in the map, then that is
    a def-use flow from the time or place at which that value was
    first observed to this instruction. Similarly, after emulating an
    instruction, we examine every value written to a register or
    memory. If a value is not in the colors map, it is a new, computed
    result and we hint about its creation and add it to the map. If it
    is in the colors map, we do nothing since it just a copy.

    Here are the kinds of hints output by this analysis

    DynamicRegisterValueHint
    -- about value in a register at a particular instruction in the trace

    DynamicMemoryValueHint
    -- about a value in memory at a particular instruction in the trace

    These can be "new" values if that is first time we have seen that
    color (dynamic value).  Or they can be not-new, meaning this is a
    use of that value previously observed, i.e. a data flow.

    They can also be reads or writes.

    Note: Why is there a min_color in constructor to Colorizer?  A
    color (here) is just a dynamic value that we think might be kinda
    unique and thus we can intuit data flows when we see it used in
    multiple places. Obviously, a color of 0 is not helpful. If you
    see 0 in two places it's unlikely that means there was a
    dataflow. But this begs the question: what is a reasonable minimum
    acceptable color for intuiting data flows?  0-10 seems like they
    can't be good colors?  Here, our default value for min color is
    0x80: this is fairly conservative and can be lowered.  Note that
    generally, we use `randomize_unitialized`, above, to set 2, 4, and
    8-byte registers and memory lvals to random numbers that will work
    well as colors.  These are unlikely to be < 0x80.

    Arguments:
        exec_id: An integer used to identify this execution, if needed
        num_insns: The number of instructions to micro-execute
        min_color: see above, min dyn value to be a color

    """

    name = "colorizer"
    description = "it's almost taint"
    version = "0.0.1"

    def __init__(
        self,
        *args,
        exec_id: int,
        num_insns: int = 200,
        # see above for explanation of this min_color stuff
        min_color: int = 0x80,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.exec_id = exec_id
        self.num_insns = num_insns
        self.colors: Colors = {}
        self.shadow_register: typing.Dict[str, Shad] = {}
        self.shadow_memory: Shad = {}
        self.min_color = min_color
        # self.edge: typing.Dict[int, typing.Dict[int, typing.Tuple[str, int, int]]] = {}

    def _get_instr_at_pc(self, emu, pc: int) -> capstone.CsInsn:
        code = emu.read_memory(pc, 15)  # longest possible instruction
        if code is None:
            raise AnalysisRunError(
                "Unable to read next instruction out of emulator memory"
            )
        insns, disas = emu._disassemble(code, pc, 2)
        insn = insns[0]
        return insn

    def _operand_size(self, operand: Operand) -> int:
        if type(operand) is RegisterOperand:
            # return size of a reg based on its name
            return self.pdef.registers[operand.name].size
        elif isinstance(operand, BSIDMemoryReferenceOperand):
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

        def check_rws(
            emu,
            pc,
            te,
            is_read,
            write_addresses=None,
            sw_insn=None,
            operand_list=None,
        ):
            # sw_insn / operand_list let a caller pass in results it has
            # already computed for this pc, so reads/writes -- which run
            # through the pyghidra-backed analysis -- aren't re-derived.
            if sw_insn is None:
                cs_insn = self._get_instr_at_pc(emu, pc)
                sw_insn = Instruction.from_capstone(cs_insn)
            logger.debug(f"instr={sw_insn}")
            if operand_list is None:
                operand_list = sw_insn.reads if is_read else sw_insn.writes
            logger.debug(f"{'reads' if is_read else 'writes'}={operand_list}")
            rws = []
            for operand in operand_list:
                if type(operand) is RegisterOperand:
                    # flow through the flags register is not tracked
                    if operand.name in ("rflags", "eflags", "flags"):
                        continue
                sz = self._operand_size(operand)
                addr = None
                if isinstance(operand, BSIDMemoryReferenceOperand):
                    if write_addresses is None:
                        addr = operand.address(emu)
                    elif operand in write_addresses:
                        addr = write_addresses[operand]
                    else:
                        # Can't happen: both callbacks disassemble the
                        # same pc, so they see the same operands.
                        logger.debug(f"no captured address for write {operand}")
                        continue
                    # if addr not mapped, discard this operand
                    if not emu._is_address_range_mapped((addr, addr + sz)):
                        continue
                    # Read the value at the address captured before the
                    # instruction ran, not one recomputed from the
                    # current registers.
                    conc = emu.read_memory(addr, sz)
                else:
                    conc = operand.concretize(emu)
                color = self._concrete_val_to_color(conc, sz)
                tup = (operand, conc, color, sz, addr)
                rws.append(tup)
            rws.sort(key=lambda e: e[0].__repr__())
            if len(rws) == 0:
                return
            for rw in rws:
                operand, conc, color, sz, addr = rw
                if color == BAD_COLOR:
                    pass
                else:
                    self._check_color(emu, is_read, rw, sw_insn, te.ic)
                # keep pls!
                # self.update_shadow(emu, pc, is_read, rw)
            if is_read:
                self.reads = rws

        def before_instruction_cb(emu, pc, te):
            cs_insn = self._get_instr_at_pc(emu, pc)
            sw_insn = Instruction.from_capstone(cs_insn)
            check_rws(emu, pc, te, True, sw_insn=sw_insn)
            # A memory operand names registers, and its address is
            # defined by their values at instruction *entry* -- so it
            # has to be resolved now. The instruction may modify a
            # register its own write address depends on (x86 push and
            # string ops, AArch64 pre/post-index, PPC update forms),
            # in which case resolving afterwards names the wrong cell.
            # Stash the write operands too, so after_instruction_cb
            # reuses them instead of re-running the analysis.
            writes = sw_insn.writes
            self._pending_write_insn = sw_insn
            self._pending_writes = writes
            self.write_addresses = {
                operand: operand.address(emu)
                for operand in writes
                if isinstance(operand, BSIDMemoryReferenceOperand)
            }

        def after_instruction_cb(emu, pc, te):
            # note: we have to check writes *after* the instruction
            # executes since we might be writing a computed value
            # which we'll only know the value (color) of after the
            # instruction executes! The addresses written, and the
            # write operands themselves, come from the pre-instruction
            # capture above.
            check_rws(
                emu,
                pc,
                te,
                False,
                self.write_addresses,
                sw_insn=self._pending_write_insn,
                operand_list=self._pending_writes,
            )

        self.colors = {}
        self.write_addresses = {}
        self._pending_write_insn = None
        self._pending_writes = []
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
        # A concrete value is either an int (from a register) or bytes (from a
        # memory read). We fold both to one integer "color" so that the same
        # value has the same color regardless of where it lives. Memory bytes
        # are interpreted in the *target's* byte order, so a register value and
        # its stored image agree on big-endian targets as well as little-endian
        # ones -- otherwise a plain store looks like it creates a new value on
        # big-endian.
        byteorder = self.platform.byteorder.value  # "big" or "little"
        if type(concrete_value) is int:
            n = concrete_value
        elif (type(concrete_value) is bytes) or (type(concrete_value) is bytearray):
            n = int.from_bytes(concrete_value, byteorder=byteorder)
        else:
            assert 1 == 0
        if n < self.min_color:
            return BAD_COLOR
        # A 128-bit value (xmm, ...) doesn't fit a 64-bit color; fold the halves.
        if size == 16:
            return (n & ((1 << 64) - 1)) ^ (n >> 64)
        return n & ((1 << (8 * size)) - 1)

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
        operand, conc, color, operand_size, address = rw
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
                address,
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
                address,
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
        address: typing.Optional[int] = None,
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
        elif isinstance(operand, BSIDMemoryReferenceOperand):
            segment_name = "None"
            if operand.segment is not None:
                segment_name = operand.segment
            base_name = "None"
            if operand.base is not None:
                base_name = operand.base
            index_name = "None"
            if operand.index is not None:
                index_name = operand.index
            return hinting.DynamicMemoryValueHint(
                time=self.htime(),
                address=(address if address is not None else operand.address(emu)),
                segment=segment_name,
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
