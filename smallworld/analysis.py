import abc
import base64
import logging
import random

from . import executable, executors, hinting, state

logger = logging.getLogger(__name__)
hinter = hinting.getHinter(__name__)


class Analysis:
    """The base class for all analyses."""

    def __init__(self, config):
        self.config = config

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """The name of this analysis.

        Names should be kebab-case, all lowercase, no whitespace for proper
        formatting.
        """

        return ""

    @property
    @abc.abstractmethod
    def description(self) -> str:
        """A description of this analysis.

        Descriptions should be a single sentence, lowercase, with no final
        punctuation for proper formatting.
        """

        return ""

    @property
    @abc.abstractmethod
    def version(self) -> str:
        """The version string for this analysis.

        We recommend using [Semantic Versioning](https://semver.org/).
        """

        return ""

    @abc.abstractmethod
    def run(self, image: executable.Executable) -> None:
        """Actually run the analysis.

        Arguments:
            image (Executable): The bytes of the execution image or code to run.
            state (State): A state class on which this analysis should run.
        """

        pass


class InputColorizerAnalysis(Analysis):
    def __init__(self, config):
        super().__init__(config)
        self.regular_regs_64 = [
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
        self.regular_regs_32 = ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp"]

    def name(self) -> str:
        return "input-colorizer"

    def description(self) -> str:
        return "it's almost taint"

    def version(self) -> str:
        return "0.0.1"

    def run(self, image: executable.Executable) -> None:
        """A very simple analysis using colorizing and unicorn.  We run
        multiple micro-executions of the code starting from same
        entry.  At the start of each, we randomize register values but
        also create a map from those specific values to name of
        register initialized that way.  We then single step emulation
        and *before* each instruction we check to see if any of the
        registers *used* by this instruction have colorized values,
        indicating they are likely direct copies of input registers.
        Any such uses of input registers are hinted
        """
        for i in range(self.config.num_micro_executions):
            # NB: perform more than one micro-exec
            # since paths could diverge given random intial
            # reg values
            executor = executors.UnicornExecutor(
                self.config.unicorn_arch, self.config.unicorn_mode
            )
            logger.info("-------------------------")
            logger.info(f"micro exec #{i}")
            # colorize regs before beginning this micro exec
            r0 = self.colorize_registers()
            for value, name in r0.items():
                logger.debug(f"{name} = {value:x}")

            self.config.cpu.apply(executor)
            executor.entrypoint = image.entry
            executor.exitpoint = image.entry + len(image.image)
            executor.write_register("pc", executor.entrypoint)
            for j in range(self.config.num_instructions):
                pc = executor.read_register("pc")
                code = executor.read_memory(pc, 15)  # longest possible instruction
                if code is None:
                    assert False, "impossible state"
                (instructions, disas) = executor.disassemble(code, 1)
                instruction = instructions[0]
                # pull state back out of the executor for inspection
                self.config.cpu.load(executor)
                # determine if, for this instruction (before execution)
                # any of the regs that will be read have values in colorized map
                # meaning they are uninitialized values
                rc = self.check_instruction_regs_colors(r0, instruction)
                for reg_name, input_reg_name in rc:
                    hint = hinting.InputUseHint(
                        message="Register used in instruction has same value as Input register",
                        input_register=input_reg_name,
                        #                        instruction = instruction,
                        instruction=base64.b64encode(instruction.bytes).decode(),
                        pc=pc,
                        micro_exec_num=i,
                        instruction_num=j,
                        use_register=reg_name,
                    )
                    hinter.info(hint)
                try:
                    done = executor.step()
                    if done:
                        break
                except Exception as e:
                    hint = hinting.EmulationException(
                        message="Emulation single step raised an exception",
                        instruction=base64.b64encode(instruction.bytes).decode(),
                        pc=pc,
                        micro_exec_num=i,
                        instruction_num=j,
                        exception=str(e),
                    )
                    hinter.info(hint)
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
        registers_used = self.instruction_uses(instruction)
        logger.debug(f"registers_used = {registers_used}")
        # This should be the set of registers used by this
        # instruction correspond to colorized (i.e. unitialized) values
        return self.check_register_colors(r0, registers_used)

    def instruction_uses(self, instruction):
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
        for name, stv in self.config.cpu.values.items():
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
            if (regular and (name in self.regular_regs_64)) or (not regular):
                # only colorize "regular" registers of full 64 bits
                reg.set(random.randint(0, 0xFFFFFFFFFFFFFFF))
        # but now go through all 64 and 32-bit reg aliases and record intial values
        r0 = {}
        for name, stv in self.config.cpu.values.items():
            if (type(stv) is state.Register) or (type(stv) is state.RegisterAlias):
                if (
                    regular
                    and (name in self.regular_regs_64 or name in self.regular_regs_32)
                ) or (not regular):
                    r0[stv.get()] = name
                    logger.debug(f"color[{name}] = {stv.get():x}")
        return r0

    def registers(self):
        """
        Generator to iterate over registers in the cpu
        """
        for name, stv in self.config.cpu.values.items():
            if type(stv) == state.Register:
                yield (name, stv)


class InvalidReadAnalysis(Analysis):
    def __init__(self, config):
        super().__init__(config)

    def name(self) -> str:
        return "invalid-read"

    def description(self) -> str:
        return "tries to help to figure out invalid reads"

    def version(self) -> str:
        return "0.0.1"

    def run(self, image: executable.Executable) -> None:
        executor = executors.UnicornExecutor(
            self.config.unicorn_arch, self.config.unicorn_mode
        )

        self.config.cpu.apply(executor)
        executor.entrypoint = image.entry
        executor.exitpoint = image.entry + len(image.image)
        executor.write_register("pc", executor.entrypoint)

        for j in range(self.config.num_instructions):
            pc = executor.read_register("pc")
            code = executor.read_memory(pc, 15)  # longest possible instruction
            if code is None:
                assert False, "impossible state"
            (instructions, disas) = executor.disassemble(code, 1)
            instruction = instructions[0]
            # pull state back out of the executor for inspection
            self.config.cpu.load(executor)
            try:
                done = executor.step()
                if done:
                    break
            except Exception as e:
                hint = hinting.EmulationException(
                    message="Emulation single step raised an exception",
                    instruction=base64.b64encode(instruction.bytes).decode(),
                    pc=pc,
                    micro_exec_num=i,
                    instruction_num=j,
                    exception=str(e),
                )
                hinter.info(hint)
                logger.info(e)
                break
