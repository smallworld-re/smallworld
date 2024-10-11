import copy
import logging
import typing

from .. import emulators, exceptions, hinting, instructions, state
from . import analysis

logger = logging.getLogger(__name__)
hinter = hinting.get_hinter(__name__)


class CodeCoverage(analysis.Analysis):
    """A simple analysis that logs jumps, calls, and returns.

    Arguments:
        num_instructions: The number of instructions to execute.
    """

    def __init__(self, *args, num_instructions: int = 10, **kwargs):
        super().__init__(*args, **kwargs)
        self.num_instructions = num_instructions

    name = "code-coverage"
    description = ""
    version = "0.0.1"

    def run(self, state: state.CPU) -> None:
        cpu = copy.deepcopy(state)
        emulator = emulators.UnicornEmulator(state.arch, state.mode, state.byteorder)
        cpu.apply(emulator)
        coverage: typing.Dict[int, int] = {}
        for i in range(self.num_instructions):
            pc = emulator.read_register("pc")
            if pc in coverage:
                coverage[pc] += 1
            else:
                coverage[pc] = 1

            try:
                done = emulator.step()
                if done:
                    break
            except exceptions.EmulationError as e:
                instruction = emulator.current_instruction()
                exhint = hinting.EmulationException(
                    message="Emulation single step raised an exception",
                    instruction=instructions.Instruction.from_capstone(instruction),
                    instruction_num=i,
                    exception=str(e),
                )
                hinter.info(exhint)
                break
        hint = hinting.CoverageHint(message="Coverage for execution", coverage=coverage)
        hinter.info(hint)
