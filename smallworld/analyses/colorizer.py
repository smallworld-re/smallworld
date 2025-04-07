import copy
import logging
import random
import struct
import typing

import capstone
import networkx as nx

from .. import hinting, state
from ..emulators import (
    UnicornEmulationMemoryReadError,
    UnicornEmulationMemoryWriteError,
    UnicornEmulator,
)
from ..exceptions import AnalysisRunError, EmulationBounds
from ..instructions import (
    BSIDMemoryReferenceOperand,
    Instruction,
    Operand,
    RegisterOperand,
)
from . import analysis

logger = logging.getLogger(__name__)
hinter = hinting.get_hinter(__name__)

MIN_ACCEPTABLE_COLOR_INT = 0x20
BAD_COLOR = (2**64) - 1

Colors = typing.Dict[int, typing.Tuple[Operand, int, int, Instruction, int]]


class Colorizer(analysis.Analysis):
    """A simple kind of data flow analysis via tracking distinct values
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
        seed: typing.Optional[int] = 99,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        # Create our own random so we can avoid contention.
        self.random = random.Random()
        self.seed = seed

        self.num_micro_executions = num_micro_executions
        self.num_insns = num_insns

    def _get_instr_at_pc(self, pc: int) -> capstone.CsInsn:
        code = self.emu.read_memory(pc, 15)  # longest possible instruction
        if code is None:
            raise AnalysisRunError(
                "Unable to read next instruction out of emulator memory"
            )
        (insns, disas) = self.emu._disassemble(code, pc, 2)
        insn = insns[0]
        return insn

    def _operand_size(self, operand: Operand) -> int:
        if type(operand) is RegisterOperand:
            # return size of a reg based on its name
            return getattr(self.cpu, operand.name).size
        elif type(operand) is BSIDMemoryReferenceOperand:
            # memory operand knows its size
            return operand.size
        return 0

    def run(self, machine: state.Machine) -> None:
        # note that start pc is in start_cpustate

        # collect hints for each microexecution, in a list of lists
        hint_list_list: typing.List[typing.List[hinting.Hint]] = []

        self.orig_machine = copy.deepcopy(machine)
        self.orig_cpu = self.orig_machine.get_cpu()
        self.platform = self.orig_cpu.platform

        edges: typing.Dict[int, typing.Dict[int, int]] = {}
        if self.seed is not None:
            self.random.seed(a=self.seed)

        for i in range(1, 1 + self.num_micro_executions):
            logger.info("-------------------------")
            logger.info(f"micro exec #{i}")

            self.machine = copy.deepcopy(self.orig_machine)
            self.cpu = self.machine.get_cpu()
            self.emu = UnicornEmulator(self.platform)
            self.machine.apply(self.emu)

            # initialize registers with random values
            self._randomize_registers()

            # map from color values to first use / def
            self.colors: Colors = {}

            hint_list: typing.List[hinting.Hint] = []
            last_pc = None
            for j in range(self.num_insns):
                logger.info(f"instr_count = {j}")
                # obtain instr about to be emulated
                pc = self.emu.read_register("pc")
                if last_pc is not None:
                    if last_pc not in edges:
                        edges[last_pc] = {}
                    if pc not in edges[last_pc]:
                        edges[last_pc][pc] = 1
                    else:
                        edges[last_pc][pc] += 1
                    # cfg.add_edge(f"{last_pc:x}", f"{pc:x}")
                # cfg.add_node(f"{pc:x}")
                if pc in self.emu.get_exit_points():
                    break
                cs_insn = self._get_instr_at_pc(pc)
                sw_insn = Instruction.from_capstone(cs_insn)

                logger.debug(sw_insn)

                # pull state back out of the emulator for inspection
                m = copy.deepcopy(self.machine)
                m.extract(self.emu)
                self.cpu = m.get_cpu()

                reads: typing.List[typing.Tuple[Operand, int, int]] = []
                for read_operand in sw_insn.reads:
                    logger.debug(f"pc={pc:x} read_operand={read_operand}")

                    if (
                        type(read_operand) is RegisterOperand
                        and read_operand.name == "rflags"
                    ):
                        continue

                    sz = self._operand_size(read_operand)
                    if type(read_operand) is BSIDMemoryReferenceOperand:
                        a = read_operand.address(self.emu)
                        ar = (a, a + sz)
                        if not self.emu._is_address_range_mapped(ar):
                            # at least one byte in this range is not mapped
                            # so dont add this read to the list
                            continue
                    read_operand_color = self._concrete_val_to_color(
                        read_operand.concretize(self.emu), sz
                    )
                    # discard bad colors
                    if read_operand_color == BAD_COLOR:
                        continue
                    tup = (read_operand, read_operand_color, sz)
                    reads.append(tup)
                reads.sort(key=lambda e: e[0].__repr__())
                #                logger.info(f"reads: {reads}")
                self._check_colors_instruction_reads(reads, sw_insn, i, j, hint_list)

                try:
                    # print(f"pc={pc:x} {sw_insn}")
                    # import pdb
                    # pdb.set_trace()

                    self.emu.step()

                except EmulationBounds:
                    logger.info(
                        "emulation complete. encountered exit point or went out of bounds"
                    )
                    break
                except UnicornEmulationMemoryWriteError as e:
                    for write_operand, addr in e.details["unmapped_writes"]:
                        h = self._mem_unavailable_hint(
                            write_operand, addr, e.pc, i, j, False
                        )
                        hint_list.append(h)
                    break
                except UnicornEmulationMemoryReadError as e:
                    for read_operand, addr in e.details["unmapped_reads"]:
                        h = self._mem_unavailable_hint(
                            read_operand, addr, e.pc, i, j, True
                        )
                        hint_list.append(h)
                    break
                except Exception as e:
                    # emulating this instruction failed
                    exhint = hinting.EmulationException(
                        message=f"In analysis, single step raised an exception {e}",
                        pc=pc,
                        instruction_num=j,
                        exception=str(e),
                    )
                    hint_list.append(exhint)
                    hinter.debug(exhint)
                    logger.info(e)
                    break

                writes: typing.List[typing.Tuple[Operand, int, int]] = []

                for write_operand in sw_insn.writes:
                    logger.debug(f"pc={pc:x} write_operand={write_operand}")

                    if (
                        type(write_operand) is RegisterOperand
                        and write_operand.name == "rflags"
                    ):
                        continue

                    sz = self._operand_size(write_operand)
                    try:
                        write_operand_color = self._concrete_val_to_color(
                            write_operand.concretize(self.emu), sz
                        )
                        # discard bad colors
                        if write_operand_color == BAD_COLOR:
                            continue
                    except Exception as e:
                        print(e)
                        h = self._mem_unavailable_hint(
                            write_operand,
                            write_operand.address(self.emu),
                            pc,
                            i,
                            j,
                            False,
                        )
                        hint_list.append(h)
                        continue
                    tup = (write_operand, write_operand_color, sz)
                    writes.append(tup)
                writes.sort(key=lambda e: e[0].__repr__())
                # import pdb
                # pdb.set_trace()
                self._check_colors_instruction_writes(writes, sw_insn, i, j, hint_list)
                last_pc = pc

            hint_list_list.append(hint_list)

        pcn: typing.Dict[int, int] = {}
        for pc1 in edges.keys():
            if pc1 not in pcn:
                pcn[pc1] = len(pcn) + 1
            for pc2 in edges[pc1]:
                if pc2 not in pcn:
                    pcn[pc2] = len(pcn) + 1

        pcs = list(pcn.keys())

        cfg = nx.MultiDiGraph()
        pos = {}
        with open("cfg.dot", "w") as d:
            d.write("digraph{\n")

            for pc in pcs:
                pos[pc] = (30, 100 * pcn[pc])
                d.write(f' {pcn[pc]} [label="0x{pc:x}"]\n')

            for pc1 in edges.keys():
                lpc1 = f"{pc1:x}"
                cfg.add_node(lpc1)
                for pc2 in edges[pc1]:
                    lpc2 = f"{pc2:x}"
                    cfg.add_node(lpc2)
                    cfg.add_edge(lpc1, lpc2, label=f"c={edges[pc1][pc2]}")
                    d.write(f' {pcn[pc1]} -> {pcn[pc2]} [label="{edges[pc1][pc2]}"];\n')
            d.write("}\n")

        logger.info("-------------------------")

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
        num_bytes = len(the_bytes)
        if num_bytes < 8:
            the_bytes = (8 - num_bytes) * b"\0" + the_bytes
        return struct.unpack("<Q", the_bytes)[0]

    def _randomize_registers(self) -> None:
        for reg in self.orig_cpu:
            # only colorize the "regular" registers
            if (type(reg) is not state.Register) or (
                reg.name not in self.orig_cpu.get_general_purpose_registers()
            ):
                continue
            orig_val = self.emu.read_register(reg.name)
            logger.debug(f"_randomize_registers {reg.name} orig_val={orig_val:x}")
            new_val = 0
            bc = 0
            for i in range(0, reg.size):
                new_val = new_val << 8
                if (
                    reg.name in self.emu.initialized_registers
                    and i in self.emu.initialized_registers[reg.name]
                ):
                    bs = 8 * (reg.size - i - 1)
                    b = (orig_val >> bs) & 0xFF
                    # b = (orig_val >> (i * 8)) & 0xFF
                    new_val |= b
                else:
                    new_val |= self.random.randint(0, 255)
                    bc += 1
            if bc == 0:
                logger.debug(
                    f"Not colorizing register {reg.name} since it is already fully initialized with {orig_val:x}"
                )
            else:
                # make sure to update cpu as well as emu not sure why
                self.emu.write_register(reg.name, new_val)
                setattr(self.cpu, reg.name, new_val)
                logger.debug(
                    f"Colorized {bc} bytes in register {reg.name}, old value was {orig_val:x} new is {new_val:x}"
                )

    # helper for read/write unavailable hint
    def _mem_unavailable_hint(
        self,
        operand: typing.Optional[BSIDMemoryReferenceOperand],
        addr: int,
        pc: int,
        exec_num: int,
        insn_num: int,
        is_read: bool,
    ) -> hinting.Hint:
        (base_name, base_val) = ("None", 0)
        (index_name, index_val) = ("None", 0)
        (operand_size, operand_scale, operand_offset, operand_address) = (0, 0, 0, 0)
        if operand:
            operand_size = operand.size
            operand_scale = operand.scale
            operand_offset = operand.offset
            operand_address = operand.address(self.emu)
            if operand.base is not None:
                base_val = self.emu.read_register(operand.base)
                base_name = operand.base
            if operand.index is not None:
                index_val = self.emu.read_register(operand.index)
                index_name = operand.index
        hint = hinting.MemoryUnavailableHint(
            is_read=is_read,
            size=operand_size,
            base_reg_name=base_name,
            base_reg_val=base_val,
            index_reg_name=index_name,
            index_reg_val=index_val,
            offset=operand_offset,
            scale=operand_scale,
            address=operand_address,
            pc=pc,
            micro_exec_num=exec_num,
            instruction_num=insn_num,
            message="mem_unavailable",
        )
        hinter.debug(hint)
        return hint

    def _add_color(
        self,
        color: int,
        operand: Operand,
        insn: Instruction,
        exec_num: int,
        insn_num: int,
    ) -> None:
        self.colors[color] = (operand, exec_num, insn_num, insn, 1 + len(self.colors))

    def _check_colors_instruction_reads(
        self,
        reads: typing.List[typing.Tuple[Operand, int, int]],
        insn: Instruction,
        exec_num: int,
        insn_num: int,
        hint_list: typing.List[hinting.Hint],
    ):
        for operand, color, operand_size in reads:
            if color in self.colors.keys():
                # read-flow: use of a previously recorded color value
                hint = self._dynamic_value_hint(
                    operand,
                    operand_size,
                    color,
                    insn,
                    True,
                    False,
                    exec_num,
                    insn_num,
                    "read-flow",
                )
                hinter.debug(hint)
                hint_list.append(hint)
            else:
                # red-def: use of a NOT previously recorded color value. As
                # long as the value is something reasonable, we'll record it as
                # a new color
                self._add_color(color, operand, insn, exec_num, insn_num)
                hint = self._dynamic_value_hint(
                    operand,
                    operand_size,
                    color,
                    insn,
                    True,
                    True,
                    exec_num,
                    insn_num,
                    "read-def",
                )
                hinter.debug(hint)
                hint_list.append(hint)

    def _check_colors_instruction_writes(
        self,
        writes: typing.List[typing.Tuple[Operand, int, int]],
        insn: Instruction,
        exec_num: int,
        insn_num: int,
        hint_list: typing.List[hinting.Hint],
    ):
        # NB: This should be called *AFTER the instruction emulates!
        for operand, color, operand_size in writes:
            if color in self.colors.keys():
                # write of a previously seen value
                # ... its just a copy so no hint, right?
                hint = self._dynamic_value_hint(
                    operand,
                    operand_size,
                    color,
                    insn,
                    False,
                    False,
                    exec_num,
                    insn_num,
                    "write-copy",
                )
                hinter.debug(hint)
                hint_list.append(hint)
                pass
            else:
                # write-def: write of a NOT previously recorded color value as
                # long as the value is something reasonable, we'll record it as
                # a new color
                self._add_color(color, operand, insn, exec_num, insn_num)
                hint = self._dynamic_value_hint(
                    operand,
                    operand_size,
                    color,
                    insn,
                    False,
                    True,
                    exec_num,
                    insn_num,
                    "write-def",
                )
                hinter.debug(hint)
                hint_list.append(hint)

    def _dynamic_value_hint(
        self,
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
                # instruction=insn,
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
                address=operand.address(self.emu),
                base=base_name,
                index=index_name,
                scale=operand.scale,
                offset=operand.offset,
                color=color,
                dynamic_value=color,
                size=operand.size,
                use=is_use,
                new=is_new,
                # instruction=insn,
                pc=pc,
                micro_exec_num=exec_num,
                instruction_num=insn_num,
                message=message,
            )
        else:
            assert 1 == 0
