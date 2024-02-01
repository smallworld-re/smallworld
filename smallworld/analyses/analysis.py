import abc
import logging

from .. import emulators, hinting, state
from ..exceptions import AnalysisSetupError

logger = logging.getLogger(__name__)
hinter = hinting.getHinter(__name__)


class Analysis:
    """The base class for all analyses."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """The name of this analysis.

        Names should be kebab-case, all lowercase, no whitespace for proper
        formatting.
        """
        pass

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
    def run(self, image: emulators.Code, state: state.CPU) -> None:
        """Actually run the analysis.

        This function **should not** modify the provided State - instead, it
        should be coppied before modification.

        Arguments:
            image (Code): The bytes of the execution image or code to run.
            state (CPU): A state class on which this analysis should run.
        """

        pass


class UnicornDebugAnalysis(Analysis):
    def __init__(self, *args, num_instructions: int = 10, **kwargs):
        super().__init__(*args, **kwargs)

        self.num_instructions = num_instructions

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
            value = self.emulator.read_register(reg)
            hint = hinting.UnderSpecifiedRegisterHint(
                message="", register=reg, value=value
            )
        elif i.type == capstone.x86.X86_OP_MEM:
            base, index, offset, base_value, index_value = "", "", 0, 0, 0
            if i.value.mem.base != 0:
                base = insn.reg_name(i.value.mem.base)
                base_value = self.emulator.read_register(base)
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

    def run(self, image: emulators.Code, state: state.CPU) -> None:
        """A very simple analysis that debugs an execution
        before an emulation."""

        self.emulator = emulators.UnicornEmulator(state.arch, state.mode)

        state.apply(self.emulator)
        self.emulator.entrypoint = image.entry
        if image.entry is None:
            raise AnalysisSetupError("image.entry is None")
        self.emulator.exitpoint = image.entry + len(image.image)
        self.emulator.write_register("pc", self.emulator.entrypoint)

        for j in range(self.num_instructions):
            # Disassemble instruction
            pc = self.emulator.read_register("pc")
            pc_bytes = self.emulator.read_memory(pc, 15)
            if pc_bytes is None:
                assert False, "impossible state"
            (instructions, disas) = self.emulator.disassemble(pc_bytes, 1)
            insn = instructions[0]

            # print("0x%x:\t%s\t%s" %(pc, insn.mnemonic, insn.op_str))

            # Try running instruction
            try:
                done = self.emulator.step()
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
