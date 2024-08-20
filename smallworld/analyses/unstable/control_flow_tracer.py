import copy
import logging

from .. import emulators, exceptions, hinting, instructions, state
from . import analysis

logger = logging.getLogger(__name__)
hinter = hinting.getHinter(__name__)


class ControlFlowTracer(analysis.Analysis):
    """A simple analysis that logs jumps, calls, and returns.

    Arguments:
        num_instructions: The number of instructions to execute.
    """

    def __init__(self, *args, num_instructions: int = 10, **kwargs):
        super().__init__(*args, **kwargs)
        self.num_instructions = num_instructions

    name = "control-flow-tracer"
    description = ""
    version = "0.0.1"

    def run(self, state: state.CPU) -> None:
        cpu = copy.deepcopy(state)
        emulator = emulators.UnicornEmulator(state.arch, state.mode, state.byteorder)
        cpu.apply(emulator)

        from_instruction = None

        for i in range(self.num_instructions):
            instruction = emulator.current_instruction()
            if from_instruction:
                hint = hinting.ControlFlowHint(
                    message="Control Flow Change",
                    from_instruction=instructions.Instruction.from_capstone(
                        from_instruction
                    ),
                    to_instruction=instructions.Instruction.from_capstone(instruction),
                )
                hinter.info(hint)
                from_instruction = None
            if self.is_cfi(instruction):
                from_instruction = instruction
            try:
                done = emulator.step()
                if done:
                    break
            except exceptions.EmulationError as e:
                exhint = hinting.EmulationException(
                    message="Emulation single step raised an exception",
                    instruction=instructions.Instruction.from_capstone(instruction),
                    instruction_num=i,
                    exception=str(e),
                )
                hinter.info(exhint)
                break

    def is_cfi(self, instruction):
        for g in instruction.groups:
            group_name = instruction.group_name(g)
            if group_name == "jump":
                return True
            elif group_name == "call":
                return True
            elif group_name == "ret":
                return True
        return False
