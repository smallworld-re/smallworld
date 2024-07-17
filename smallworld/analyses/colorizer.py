import base64
import copy
import logging
import random
import typing

import capstone

from .. import hinting, state
from ..emulators import UnicornEmulator
from ..exceptions import AnalysisRunError
from ..instructions import (
    BSIDMemoryReferenceOperand,
    Instruction,
    Operand,
    RegisterOperand,
)
from . import analysis

logger = logging.getLogger(__name__)
hinter = hinting.getHinter(__name__)

MIN_ACCEPTABLE_COLOR_INT = 20
BAD_COLOR = "BAD_COLOR"

Colors = typing.Dict[str, typing.Tuple[Operand, int, int, Instruction, int]]


class ColorizerAnalysis(analysis.Analysis):
    """A simple kind of data flow analysis via tracking distinct values (colors)
    and employing instruction use/def analysis

    We run multiple micro-executions of the code starting from same entry. At
    the start of each, we randomize register values that have not already been
    initialized. We maintain a "colors" map from values to when we first
    observed them. This map is initially empty. Before emulating an instruction,
    we examine the values (registers and memory) it will read. If any are NOT in
    the colors map, that is the initial sighting of that value and we emit a
    hint to that effect. If any color IS already in the map, then that is a flow
    from the time at which that value was first observed to this
    instruction. Similarly, after emulating an instruction, we examine every
    value (register and memory) written. If a value is not in the colors map, it
    is a new, computed result and we hint about its creation. If it is in the
    colors map, we do nothing since it just a copy.

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
        num_micro_executions: int = 5,
        num_insns: int = 10,
        seed: typing.Optional[int] = 99,
        **kwargs
        #        self, *args, num_micro_executions: int = 1, num_insns: int = 10, **kwargs
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
        (insns, disas) = self.emu.disassemble(code, pc, 2)
        insn = insns[0]
        return insn

    def _operand_size(self, operand: Operand) -> int:
        if type(operand) is RegisterOperand:
            # return size of a reg based on its name
            return getattr(self.cpu, operand.name).width
        elif type(operand) is BSIDMemoryReferenceOperand:
            # memory operand knows its size
            return operand.size
        return 0

    def run(self, start_cpustate: state.CPU) -> None:
        # note that start pc is in start_cpustate

        # collect hints for each microexecution, in a list of lists
        hint_list_list: typing.List[typing.List[hinting.Hint]] = []

        for i in range(self.num_micro_executions):
            logger.info("-------------------------")
            logger.info(f"micro exec #{i}")

            if self.seed is not None:
                self.random.seed(a=self.seed)

            self.cpu = copy.deepcopy(start_cpustate)
            self.emu = UnicornEmulator(self.cpu.arch, self.cpu.mode, self.cpu.byteorder)

            # initialize registers with random values
            self._randomize_registers()

            # map from color values to first use / def
            self.colors: Colors = {}

            # copy regs and any stack / heap init
            # and load the code to analyze into emulator
            self.cpu.apply(self.emu)

            hint_list = []
            for j in range(self.num_insns):
                # obtain instr about to be emulated
                pc = self.emu.read_register("pc")
                cs_insn = self._get_instr_at_pc(pc)
                sw_insn = Instruction.from_capstone(cs_insn)

                logger.debug(sw_insn)

                # pull state back out of the emulator for inspection
                self.cpu.load(self.emu)

                reads: typing.List[typing.Tuple[Operand, str, int]] = []
                for read_operand in sw_insn.reads:
                    logger.debug(f"pc={pc:x} read_operand={read_operand}")
                    sz = self._operand_size(read_operand)
                    try:
                        read_operand_color = self._concrete_val_to_color(
                            read_operand.concretize(self.emu), sz
                        )
                        # discard bad colors
                        if read_operand_color == BAD_COLOR:
                            continue
                    except Exception as e:
                        print(e)
                        h = self._mem_unavailable_hint(
                            read_operand, sw_insn, pc, i, j, True
                        )
                        hint_list.append(h)
                        continue
                    tup = (read_operand, read_operand_color, sz)
                    reads.append(tup)
                reads.sort(key=lambda e: e[0].__repr__())
                #                logger.info(f"reads: {reads}")
                self._check_colors_instruction_reads(reads, sw_insn, i, j, hint_list)

                try:
                    done = self.emu.step()
                except Exception as e:
                    # emulating this instruction failed
                    exhint = hinting.EmulationException(
                        message=f"In analysis, single step raised an exception {e}",
                        instruction=sw_insn,
                        instruction_num=j,
                        exception=str(e),
                    )
                    hint_list.append(exhint)
                    hinter.debug(exhint)
                    logger.info(e)
                    break

                writes: typing.List[typing.Tuple[Operand, str, int]] = []
                for write_operand in sw_insn.writes:
                    logger.debug(f"pc={pc:x} write_operand={write_operand}")
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
                            write_operand, sw_insn, pc, i, j, False
                        )
                        hint_list.append(h)
                        continue
                    tup = (write_operand, write_operand_color, sz)
                    writes.append(tup)
                writes.sort(key=lambda e: e[0].__repr__())
                self._check_colors_instruction_writes(writes, sw_insn, i, j, hint_list)

                if done:
                    break

            hint_list_list.append(hint_list)

        logger.info("-------------------------")

        # if two hints map to the same key then they are in same equivalence class
        def hint_key(hint):
            if type(hint) is hinting.DynamicRegisterValueHint:
                return (
                    "dynamic_register_value",
                    hint.pc,
                    not hint.use,
                    hint.color,
                    hint.new,
                    hint.message,
                    hint.reg_name,
                )
            if type(hint) is hinting.DynamicMemoryValueHint:
                return (
                    "dynamic_memory_value",
                    hint.pc,
                    not hint.use,
                    hint.color,
                    hint.new,
                    hint.message,
                    hint.base,
                    hint.index,
                    hint.scale,
                    hint.offset,
                )
            if type(hint) is hinting.MemoryUnavailableHint:
                return (
                    "memory_unavailable",
                    hint.pc,
                    hint.size,
                    hint.message,
                    hint.base_reg_name,
                    hint.index_reg_name,
                    hint.offset,
                    hint.scale,
                )
            if type(hint) is hinting.EmulationException:
                return (
                    "emulation_exception",
                    hint.instruction.__str__(),
                    hint.instruction_num,
                    hint.exception,
                )

        all_hint_keys = set([])
        hk_exemplar = {}
        for hint_list in hint_list_list:
            for hint in hint_list:
                hk = hint_key(hint)
                all_hint_keys.add(hk)
                # keep one exemplar
                if hk not in hk_exemplar:
                    hk_exemplar[hk] = hint

        hint_keys_sorted = sorted(list(all_hint_keys))

        # given the equivalence classes established by `hint_key`, determine
        # which of those were observed in each micro-execution
        hk_observed: typing.Dict[
            int, typing.Set[typing.Tuple[int, bool, str, bool, str, str, str, int, int]]
        ] = {}
        for me in range(self.num_micro_executions):
            hk_observed[me] = set([])
            for hint in hint_list_list[me]:
                # this hint key was observed in micro execution me
                hk_observed[me].add(hint_key(hint))

        # estimate "probability" of observing a hint in an equiv class as
        # fraction of micro executions in which it was observed at least once
        hk_c = {}
        for hk in hint_keys_sorted:
            hk_c[hk] = 0
            for me in range(self.num_micro_executions):
                for hk2 in hk_observed[me]:
                    if hk == hk2:
                        hk_c[hk] += 1

        for hk in hint_keys_sorted:
            prob = (float(hk_c[hk])) / self.num_micro_executions
            assert prob <= 1.0
            hint = hk_exemplar[hk]

            if type(hint) is hinting.DynamicRegisterValueHint:
                hinter.info(
                    hinting.DynamicRegisterValueProbHint(
                        instruction=hint.instruction,
                        pc=hint.pc,
                        reg_name=hint.reg_name,
                        color=hint.color,
                        size=hint.size,
                        use=hint.use,
                        new=hint.new,
                        prob=prob,
                        message=hint.message + "-prob",
                    )
                )
            if type(hint) is hinting.DynamicMemoryValueHint:
                hinter.info(
                    hinting.DynamicMemoryValueProbHint(
                        instruction=hint.instruction,
                        pc=hint.pc,
                        size=hint.size,
                        base=hint.base,
                        index=hint.index,
                        scale=hint.scale,
                        offset=hint.offset,
                        color=hint.color,
                        use=hint.use,
                        new=hint.new,
                        prob=prob,
                        message=hint.message + "-prob",
                    )
                )
            if type(hint) is hinting.MemoryUnavailableHint:
                hinter.info(
                    hinting.MemoryUnavailableProbHint(
                        is_read=hint.is_read,
                        size=hint.size,
                        base_reg_name=hint.base_reg_name,
                        index_reg_name=hint.index_reg_name,
                        offset=hint.offset,
                        scale=hint.scale,
                        instruction=hint.instruction,
                        pc=hint.pc,
                        prob=prob,
                        message=hint.message + "-prob",
                    )
                )

    def _concrete_val_to_color(
        self, concrete_value: typing.Union[int, bytes, bytearray], size: int
    ) -> str:
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
        return base64.b64encode(the_bytes).decode()

    def _randomize_registers(self) -> None:
        for name, reg in self.cpu.members(state.Register).items():
            # only colorize the "regular" registers
            if name not in self.cpu.GENERAL_PURPOSE_REGS:
                continue
            # !! don't colorize a register that has already been initialized
            if not (reg.value is None):
                logger.debug(
                    f"Not colorizing register {name} since it is already initialized with {reg.value:x}"
                )
                continue
            val = self.random.randint(0, 0xFFFFFFFFFFFFFFF)
            reg.value = val
            logger.debug(f"Colorizing register {name} with {val:x}")

    # helper for read/write unavailable hint
    def _mem_unavailable_hint(
        self,
        operand: BSIDMemoryReferenceOperand,
        insn: Instruction,
        pc: int,
        exec_num: int,
        insn_num: int,
        is_read: bool,
    ) -> hinting.Hint:
        (base_name, base_val) = ("None", 0)
        if operand.base is not None:
            base_val = self.emu.read_register(operand.base)
            base_name = operand.base
        (index_name, index_val) = ("None", 0)
        if operand.index is not None:
            index_val = self.emu.read_register(operand.index)
            index_name = operand.index
        hint = hinting.MemoryUnavailableHint(
            is_read=is_read,
            size=operand.size,
            base_reg_name=base_name,
            base_reg_val=base_val,
            index_reg_name=index_name,
            index_reg_val=index_val,
            offset=operand.offset,
            scale=operand.scale,
            address=operand.address(self.emu),
            instruction=insn,
            pc=pc,
            micro_exec_num=exec_num,
            instruction_num=insn_num,
            message="mem_unavailable",
        )
        hinter.debug(hint)
        return hint

    def _get_color_num(self, color: str) -> int:
        (_, _, _, _, color_num) = self.colors[color]
        return color_num

    def _add_color(
        self,
        color: str,
        operand: Operand,
        insn: Instruction,
        exec_num: int,
        insn_num: int,
    ) -> None:
        self.colors[color] = (operand, exec_num, insn_num, insn, 1 + len(self.colors))

    def _check_colors_instruction_reads(
        self,
        reads: typing.List[typing.Tuple[Operand, str, int]],
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
                # logger.info(
                #    f"new color {color} color_num {self._get_color_num(color)} instruction [{insn}] operand {operand}"
                # )
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
        writes: typing.List[typing.Tuple[Operand, str, int]],
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
                pass
            else:
                # write-def: write of a NOT previously recorded color value as
                # long as the value is something reasonable, we'll record it as
                # a new color
                self._add_color(color, operand, insn, exec_num, insn_num)
                # logger.info(
                #    f"new color {color} color_num {self._get_color_num(color)} instruction [{insn}] operand {operand}"
                # )
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
        color: str,
        insn: Instruction,
        is_use: bool,
        is_new: bool,
        exec_num: int,
        insn_num: int,
        message: str,
    ):
        pc = insn.address
        color_num = self._get_color_num(color)
        if type(operand) is RegisterOperand:
            return hinting.DynamicRegisterValueHint(
                reg_name=operand.name,
                size=size,
                color=color_num,
                dynamic_value=color,
                use=is_use,
                new=is_new,
                instruction=insn,
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
                color=color_num,
                dynamic_value=color,
                size=operand.size,
                use=is_use,
                new=is_new,
                instruction=insn,
                pc=pc,
                micro_exec_num=exec_num,
                instruction_num=insn_num,
                message=message,
            )
        else:
            assert 1 == 0
