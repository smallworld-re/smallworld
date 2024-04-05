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
    Instruction,
    Operand,
    RegisterOperand,
    x86MemoryReferenceOperand,
)
from . import analysis

logger = logging.getLogger(__name__)
hinter = hinting.getHinter(__name__)

MIN_ACCEPTABLE_COLOR_INT = 20

Colors = typing.Dict[str, typing.Tuple[Operand, int, int, Instruction]]


class UnacceptableColorException(Exception):
    "Raised when a color is not acceptable"
    pass


class ColorizerAnalysis(analysis.Analysis):
    """A very simple analysis using colorizing and unicorn.

    We run multiple micro-executions of the code starting from same entry. At
    the start of each, we randomize register values that have not already been
    initialized. We maintain a "colors" map from values to when we first
    observed them.  This map is initially empty. Before emulating an
    instruction, we examine the values (registers and memory) it will read.  If
    any are NOT in the colors map, that is the initial sighting of that value
    and we hint.  If any are already in the colors map, then that is a flow from
    the time at which that value was first observed.  Similarly, after emulating
    the instruction, we examine every value (regstier and memory) written.  If a
    value is not in the colors map, it is a new, computed result and we hint it.
    If it is in the colors map, we do nothing since it just a copy.  Whilst
    looking at reads and writes for instructions, we hint if any correspond to
    unavailable memory.

    Arguments:
        num_micro_executions: The number of micro-executions to run.
        num_insns: The number of instructions to execute.

    """

    name = "colorizer"
    description = "it's almost taint"
    version = "0.0.1"

    REGULAR_REGS_64 = [
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rdi",
        "rsi",
        "rbp",
        "rsp",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
    ]

    REGULAR_REGS_32 = ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp"]

    def __init__(
        self,
        *args,
        num_micro_executions: int = 5,
        num_insns: int = 10,
        **kwargs
        #        self, *args, num_micro_executions: int = 1, num_insns: int = 10, **kwargs
    ):
        super().__init__(*args, **kwargs)

        self.num_micro_executions = num_micro_executions
        self.num_insns = num_insns
        self.emu = None

    def get_instr_at_pc(self, emu: UnicornEmulator, pc: int) -> capstone.CsInsn:
        code = emu.read_memory(pc, 15)  # longest possible instruction
        if code is None:
            raise AnalysisRunError(
                "Unable to read next instruction out of emulator memory"
            )
        (insns, disas) = emu.disassemble(code, pc, 2)
        insn = insns[0]
        return insn

    def run(self, cpustate: state.CPU) -> None:
        # NB: perform more than one micro-exec
        # since paths could diverge given random intial
        # reg values
        hint_list_list = []
        for i in range(self.num_micro_executions):
            self.cpu = copy.deepcopy(cpustate)

            the_code = None
            for n, s in self.cpu.values().items():
                if type(s) is state.Code:
                    the_code = s

            assert not (the_code is None)

            emu = UnicornEmulator(cpustate.arch, cpustate.mode)
            logger.info("-------------------------")
            logger.info(f"micro exec #{i}")

            # initialize registers with random values
            self.randomize_registers()

            # map from color values to first use / def
            colors: Colors = {}

            # copy regs and any stack / heap init into emulator
            # and load the code to analyze
            self.cpu.apply(emu)

            hint_list = []
            for j in range(self.num_insns):
                # obtain instr about to be emulated
                pc = emu.read_register("pc")
                cs_insn = self.get_instr_at_pc(emu, pc)
                sw_insn = Instruction.from_capstone(cs_insn)

                # pull state back out of the emulator for inspection
                self.cpu.load(emu)

                reads: typing.List[typing.Tuple[Operand, str]] = []
                for read_operand in sw_insn.reads:
                    try:
                        read_operand_color = self.concrete_val_to_color(
                            read_operand.concretize(emu), read_operand.size
                        )
                    except UnacceptableColorException:
                        continue
                    except:
                        h = self.read_unavailable_hint(
                            emu, read_operand, sw_insn, pc, i, j
                        )
                        hint_list.append(h)
                        # don't add to the list
                        continue
                    pair = (read_operand, read_operand_color)
                    reads.append(pair)
                self.check_colors_instruction_reads(
                    emu, reads, sw_insn, colors, i, j, hint_list
                )

                try:
                    done = emu.step()
                    if done:
                        break
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

                writes: typing.List[typing.Tuple[Operand, str]] = []
                for write_operand in sw_insn.writes:
                    try:
                        write_operand_color = self.concrete_val_to_color(
                            write_operand.concretize(emu), write_operand.size
                        )
                    except UnacceptableColorException:
                        continue
                    except:
                        h = self.write_unavailable_hint(
                            emu, write_operand, sw_insn, pc, i, j
                        )
                        hint_list.append(h)
                    pair = (write_operand, write_operand_color)
                    writes.append(pair)
                self.check_colors_instruction_writes(
                    emu, writes, sw_insn, colors, i, j, hint_list
                )

            hint_list_list.append(hint_list)

        logger.info("-------------------------")

        # get set across all hint list
        def hint_key(hint):
            if type(hint) is hinting.DynamicRegisterValueHint:
                return f"{hint.message},{hint.instruction},{hint.pc:x},{hint.size},{hint.use},{hint.new},{hint.reg_name}"
            if type(hint) is hinting.DynamicMemoryValueHint:
                return f"{hint.message},{hint.instruction},{hint.pc:x},{hint.size},{hint.use},{hint.new},{hint.base},{hint.index},{hint.scale},{hint.offset}"
            if type(hint) is hinting.MemoryUnavailableHint:
                return f"{hint.message},{hint.instruction},{hint.pc:x},{hint.size},{hint.is_read},{hint.base_reg_name},{hint.index_reg_name},{hint.offset},{hint.scale}"

        all_hint_keys = set([])
        for hint_list in hint_list_list:
            for hint in hint_list:
                all_hint_keys.add(hint_key(hint))

        hint_hist: typing.Dict[str, typing.List[hinting.Hint]] = {}
        for hk in all_hint_keys:
            hint_hist[hk] = []
            for hint_list in hint_list_list:
                for h in hint_list:
                    hk2 = hint_key(h)
                    if hk2 == hk:
                        hint_hist[hk].append(h)

        for key, hint_list in hint_hist.items():
            hint = hint_list[0]
            p = (float(len(hint_list))) / self.num_micro_executions
            if type(hint) is hinting.DynamicRegisterValueHint:
                hinter.info(
                    hinting.DynamicRegisterValueProbHint(
                        instruction=hint.instruction,
                        pc=hint.pc,
                        size=hint.size,
                        reg_name=hint.reg_name,
                        use=hint.use,
                        new=hint.new,
                        prob=p,
                        message=hint.message + "Count",
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
                        use=hint.use,
                        new=hint.new,
                        prob=p,
                        message=hint.message + "Count",
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
                        prob=p,
                        message=hint.message + "Count",
                    )
                )

    def concrete_val_to_color(
        self, concrete_value: typing.Union[int, bytes], size: int
    ) -> str:
        # this concrete value can be an int (if it came from a register)
        # or bytes (if it came from memory read)
        # we want these in a common format so that we can see them as colors
        the_bytes: bytes = b""
        if type(concrete_value) is int:
            if concrete_value < MIN_ACCEPTABLE_COLOR_INT:
                raise UnacceptableColorException
            the_bytes = concrete_value.to_bytes(size, byteorder="little")
        elif type(concrete_value) is bytes:
            # assuming little-endian
            if (
                int.from_bytes(concrete_value, byteorder="little")
                < MIN_ACCEPTABLE_COLOR_INT
            ):
                raise UnacceptableColorException
            the_bytes = concrete_value
        else:
            assert 1 == 0
        return base64.b64encode(the_bytes).decode()

    def randomize_registers(self) -> None:
        for name, reg in self.cpu.values().items():
            if type(reg) is state.Register:
                # only colorize the "regular" registers

                # TODO:  oops this wont work if we have a 32 bit cpu
                if not (name in self.REGULAR_REGS_64):
                    continue
                # !! don't colorize a register that has already been initialized
                if not (reg.get() is None):
                    logger.debug(
                        f"Not colorizing register {name} since it is already initialized with {reg.get():x}"
                    )
                    continue
                val = random.randint(0, 0xFFFFFFFFFFFFFFF)
                reg.set(val)
                logger.debug(f"Colorizing register {name} with {val:x}")

    # unavailable reads are hints
    def read_unavailable_hint(
        self,
        emu: UnicornEmulator,
        operand: x86MemoryReferenceOperand,
        insn: Instruction,
        pc: int,
        exec_num: int,
        insn_num: int,
    ) -> hinting.Hint:
        return self.mem_unavailable_hint(
            emu, operand, insn, pc, exec_num, insn_num, True
        )

    # unavailable writes are hints
    def write_unavailable_hint(
        self,
        emu: UnicornEmulator,
        operand: x86MemoryReferenceOperand,
        insn: Instruction,
        pc: int,
        exec_num: int,
        insn_num: int,
    ) -> hinting.Hint:
        return self.mem_unavailable_hint(
            emu, operand, insn, pc, exec_num, insn_num, False
        )

    # helper for read/write unavailable hint
    def mem_unavailable_hint(
        self,
        emu: UnicornEmulator,
        operand: x86MemoryReferenceOperand,
        insn: Instruction,
        pc: int,
        exec_num: int,
        insn_num: int,
        is_read: bool,
    ) -> hinting.Hint:
        (base_name, base_val) = ("None", 0)
        if operand.base is not None:
            base_val = emu.read_register(operand.base)
            base_name = operand.base
        (index_name, index_val) = ("None", 0)
        if operand.index is not None:
            index_val = emu.read_register(operand.index)
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
            address=operand.address(emu),
            instruction=insn,
            pc=pc,
            micro_exec_num=exec_num,
            instruction_num=insn_num,
            message="mem_unavailable",
        )
        hinter.debug(hint)
        return hint

    def check_colors_instruction_reads(
        self,
        emu: UnicornEmulator,
        reads: typing.List[typing.Tuple[Operand, str]],
        insn: Instruction,
        colors: Colors,
        exec_num: int,
        insn_num: int,
        hint_list: typing.List[hinting.Hint],
    ):
        for operand, operand_val in reads:
            if operand_val in colors:
                # use of a previously recorded color value
                # this is a flow
                hint = self.dynamic_value_hint(
                    emu,
                    operand,
                    operand_val,
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
                # use of a NOT previously recorded color value.
                # as long as the value is something reasonable,
                # we'll record it as a new coloe
                hint = self.dynamic_value_hint(
                    emu,
                    operand,
                    operand_val,
                    insn,
                    True,
                    True,
                    exec_num,
                    insn_num,
                    "read-def",
                )
                hinter.debug(hint)
                hint_list.append(hint)
                colors[operand_val] = (operand, exec_num, insn_num, insn)

    def check_colors_instruction_writes(
        self,
        emu: UnicornEmulator,
        writes: typing.List[typing.Tuple[Operand, str]],
        insn: Instruction,
        colors: Colors,
        exec_num: int,
        insn_num: int,
        hint_list: typing.List[hinting.Hint],
    ):
        # NB: This should be called *AFTER the instruction emulates!
        for operand, operand_val in writes:
            if operand_val in colors:
                # write of a previously seen value
                # ... its likely just a copy so no hint
                pass
            else:
                # write of a NOT previously recorded color value
                # as long as the value is something reasonable,
                # we'll record it as a new coloe
                hint = self.dynamic_value_hint(
                    emu,
                    operand,
                    operand_val,
                    insn,
                    False,
                    True,
                    exec_num,
                    insn_num,
                    "write-def",
                )
                hinter.debug(hint)
                hint_list.append(hint)
                colors[operand_val] = (operand, exec_num, insn_num, insn)

    def dynamic_value_hint(
        self,
        emu: UnicornEmulator,
        operand: Operand,
        operand_val: str,
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
                dynamic_value=operand_val,
                size=operand.size,
                use=is_use,
                new=is_new,
                instruction=insn,
                pc=pc,
                micro_exec_num=exec_num,
                instruction_num=insn_num,
                message=message,
            )
        elif type(operand) is x86MemoryReferenceOperand:
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
                dynamic_value=operand_val,
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
