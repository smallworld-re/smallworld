import copy
import logging
import random

from .. import analysis, emulators, hinting, state
from ..exceptions import AnalysisRunError

logger = logging.getLogger(__name__)
hinter = hinting.getHinter(__name__)


class InputColorizerAnalysis(analysis.Analysis):
    """A very simple analysis using colorizing and unicorn.

    We run multiple micro-executions of the code starting from same entry.
    At the start of each, we randomize register values but also create a
    map from those specific values to name of register initialized that
    way. We then single step emulation and *before* each instruction we
    check to see if any of the registers *used* by this instruction have
    colorized values, indicating they are likely direct copies of input
    registers. Any such uses of input registers are hinted.

    Arguments:
        num_micro_executions (int): The number of micro-executions to run.
        num_instructions (int): The number of instructions to execute.
    """

    name = "input-colorizer"
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
        self, *args, num_micro_executions: int = 5, num_instructions: int = 10, **kwargs
    ):
        super().__init__(*args, **kwargs)

        self.num_micro_executions = num_micro_executions
        self.num_instructions = num_instructions

    def run(self, image: emulators.Code, state: state.CPU) -> None:
        for i in range(self.num_micro_executions):
            self.cpu = copy.deepcopy(state)

            # NB: perform more than one micro-exec
            # since paths could diverge given random intial
            # reg values
            emu = emulators.UnicornEmulator(state.arch, state.mode)
            logger.info("-------------------------")
            logger.info(f"micro exec #{i}")
            # colorize regs before beginning this CPU exec
            r0 = self.colorize_registers()
            for value, name in r0.items():
                logger.debug(f"{name} = {value:x}")

            self.cpu.apply(emu)

            emu.load(image)

            for j in range(self.num_instructions):
                pc = emu.read_register("pc")
                code = emu.read_memory(pc, 15)  # longest possible instruction
                if code is None:
                    raise AnalysisRunError(
                        "Unable to read next instruction out of emulator memory"
                    )
                    assert False, "impossible state"
                (instructions, disas) = emu.disassemble(code, 1)
                instruction = instructions[0]
                # pull state back out of the emulator for inspection
                self.cpu.load(emu)
                # determine if, for this instruction (before execution)
                # any of the regs that will be read have values in colorized map
                # meaning they are uninitialized values
                rc = self.check_instruction_regs_colors(r0, instruction)
                for reg_name, input_reg_name in rc:
                    hint = hinting.InputUseHint(
                        message="Register used in instruction has same value as Input register",
                        input_register=input_reg_name,
                        capstone_instruction=instruction,
                        pc=pc,
                        micro_exec_num=i,
                        instruction_num=j,
                        use_register=reg_name,
                    )
                    hinter.info(hint)
                try:
                    done = emu.step()
                    if done:
                        break
                except Exception as e:
                    exhint = hinting.EmulationException(
                        message="Emulation single step raised an exception",
                        capstone_instruction=instruction,
                        pc=pc,
                        micro_exec_num=i,
                        instruction_num=j,
                        exception=str(e),
                    )
                    hinter.info(exhint)
                    logger.info(e)
                    break

    def check_instruction_regs_colors(self, r0, instruction):
        # r0 is register colors: map from initial random value at start of micro exec
        # to corresponding initial reg name
        # registers used (or read) by this instruction
        # returns a list of pairs (rn, irn)
        # where rn is the name of a register used by instruction
        # and irn is the original register name it appears to correspond to
        # based on colorizing
        (registers_uses, _) = self.instruction_usedefs(instruction)
        logger.debug(f"registers_uses = {registers_uses}")
        # This should be the set of registers used by this
        # instruction correspond to colorized (i.e. unitialized) values
        return self.check_register_colors(r0, registers_uses)

    def instruction_usedefs(self, instruction):
        # determine set of registers this instruction uses and defines
        (regs_read, regs_written) = instruction.regs_access()
        r_read = []
        for r in regs_read:
            name = instruction.reg_name(r)
            r_read.append(name)
        r_written = []
        for r in regs_written:
            name = instruction.reg_name(r)
            r_written.append(name)
        return (r_read, r_written)

    def instruction_defs(self, instruction):
        # determine set of registers this instruction uses
        (regs_read, regs_written) = instruction.regs_access()
        r_read = []
        for r in regs_read:
            name = instruction.reg_name(r)
            r_read.append(name)
        return r_read

    def check_register_colors(self, r0, reg_subset, regular=True):
        # return set of regs in reg_subset whose current value
        # is in colorized map r0
        # [relies on reg values being in self.cpu]
        r_c = []
        for name, stv in self.cpu.values.items():
            if not (
                (type(stv) is state.Register) or (type(stv) is state.RegisterAlias)
            ):
                continue
            if not (name in reg_subset):
                continue
            value = stv.get()
            logger.debug(f"check_register_colors: {name} = {value:x}")
            if (name in reg_subset) and value in r0:
                logger.debug("-- that's a color")
                # name is a register in the subset
                # *and* in the colorizer map
                # and this is name of input register it corresponds to
                input_name = r0[value]
                p = (name, input_name)
                r_c.append(p)
        return r_c

    def colorize_registers(self, regular=True):
        # colorize registers
        for name, reg in self.registers():
            if (regular and (name in self.REGULAR_REGS_64)) or (not regular):
                # only colorize "regular" registers of full 64 bits
                reg.set(random.randint(0, 0xFFFFFFFFFFFFFFF))
        # but now go through all 64 and 32-bit reg aliases and record intial values
        r0 = {}
        for name, stv in self.cpu.values.items():
            if (type(stv) is state.Register) or (type(stv) is state.RegisterAlias):
                if (
                    regular
                    and (name in self.REGULAR_REGS_64 or name in self.REGULAR_REGS_32)
                ) or (not regular):
                    r0[stv.get()] = name
                    logger.debug(f"color[{name}] = {stv.get():x}")
        return r0

    def registers(self):
        """
        Generator to iterate over registers in the cpu
        """
        for name, stv in self.cpu.values.items():
            if type(stv) is state.Register:
                yield (name, stv)
