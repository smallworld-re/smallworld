import copy
import logging
import typing

from ... import emulators, exceptions, hinting, state
from .. import analysis

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

    def run(self, state: state.Machine) -> None:
        machine = copy.deepcopy(state)
        cpu = machine.get_cpu()
        emulator = emulators.UnicornEmulator(cpu.platform)
        machine.apply(emulator)
        coverage: typing.Dict[int, int] = {}
        for i in range(self.num_instructions):
            pc = emulator.read_register_content("pc")
            if pc in coverage:
                coverage[pc] += 1
            else:
                coverage[pc] = 1

            try:
                emulator.step()
            except exceptions.EmulationStop:
                break
            except exceptions.EmulationError as e:
                exhint = hinting.EmulationException(
                    message="Emulation single step raised an exception",
                    pc=pc,
                    instruction_num=i,
                    exception=str(e),
                )
                hinter.info(exhint)
                break
        hint = hinting.CoverageHint(message="Coverage for execution", coverage=coverage)
        hinter.info(hint)
