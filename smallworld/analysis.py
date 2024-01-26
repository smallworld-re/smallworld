import abc
import logging
import random

from smallworld.exceptions import AnalysisRunError, AnalysisSetupError

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
        pass

    #        return ""

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

    @property
    def name(self) -> str:
        return "input-colorizer"

    @property
    def description(self) -> str:
        return "it's almost taint"

    @property
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
            if image.entry is None:
                raise AnalysisSetupError("image.entry is None")
            executor.exitpoint = image.entry + len(image.image)
            executor.write_register("pc", executor.entrypoint)
            for j in range(self.config.num_instructions):
                pc = executor.read_register("pc")
                code = executor.read_memory(pc, 15)  # longest possible instruction
                if code is None:
                    raise AnalysisRunError(
                        "Unable to read next instruction out of executor memory"
                    )
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
                        capstone_instruction=instruction,
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
            if type(stv) is state.Register:
                yield (name, stv)


class UnicornDebugAnalysis(Analysis):
    def __init__(self, config):
        super().__init__(config)

        self.executor = executors.UnicornExecutor(
            self.config.unicorn_arch, self.config.unicorn_mode
        )

    @property
    def name(self) -> str:
        return "unicorn-debug"

    @property
    def description(self) -> str:
        return "analyze an execution for exceptions before emulation"

    @property
    def version(self) -> str:
        return "0.0.1"

    def hint_op(self, i, insn):
        # this needs to be better but we figure out what
        # type of op we are working with (REG,MEM,IMM)
        # when something fails and give some hints for it

        # x86 instructions with capstone
        import capstone

        if i.type == capstone.x86.X86_OP_REG:
            reg = insn.reg_name(i.value.reg)
            value = self.executor.read_register(reg)
            hint = hinting.UnderSpecifiedRegisterHint(
                message="", register=reg, value=value
            )
        elif i.type == capstone.x86.X86_OP_MEM:
            base, index, offset, base_value, index_value = "", "", 0, 0, 0
            if i.value.mem.base != 0:
                base = insn.reg_name(i.value.mem.base)
                base_value = self.executor.read_register(base)
                hint = hinting.RegisterPointerHint(message="", register=base)
                hinter.info(hint)
            if i.value.mem.index != 0:
                index = insn.reg_name(i.value.mem.index)
                index_value = self.read_register(index)
            if i.value.mem.disp != 0:
                offset = i.value.mem.disp
            hint = hinting.UnderSpecifiedMemoryRefHint(
                message="",
                base=(base, base_value),
                index=(index, index_value),
                offset=offset,
            )
            hinter.info(hint)
        if i.type == capstone.x86.X86_OP_IMM:
            # not sure what I want to hint here yet
            print("IMM = 0x%x" % (i.value.imm))

    def run(self, image: executable.Executable) -> None:
        """A very simple analysis that debugs an execution
        before an emulation."""

        self.config.cpu.apply(self.executor)
        self.executor.entrypoint = image.entry
        if image.entry is None:
            raise AnalysisSetupError("image.entry is None")
        self.executor.exitpoint = image.entry + len(image.image)
        self.executor.write_register("pc", self.executor.entrypoint)

        for j in range(self.config.num_instructions):
            # Disassemble instruction
            pc = self.executor.read_register("pc")
            pc_bytes = self.executor.read_memory(pc, 15)
            if pc_bytes is None:
                assert False, "impossible state"
            (instructions, disas) = self.executor.disassemble(pc_bytes, 1)
            insn = instructions[0]

            # print("0x%x:\t%s\t%s" %(pc, insn.mnemonic, insn.op_str))

            # Try running instruction
            try:
                done = self.executor.step()
                if done:
                    break
            except Exception as e:
                # Hinting here, can provide for any unicorn errors
                from unicorn import unicorn_const as uc

                # hint = hinting.HintInstruction(pc, insn.mnemonic, pc_bytes)

                if e.args[0].errno == uc.UC_ERR_READ_UNMAPPED:
                    self.hint_op(insn.operands[1], insn)
                elif e.args[0].errno == uc.UC_ERR_WRITE_UNMAPPED:
                    self.hint_op(insn.operands[0], insn)

                break
