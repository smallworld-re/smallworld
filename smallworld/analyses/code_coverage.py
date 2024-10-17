import logging
import typing

from .. import emulators, hinting
from . import analysis

logger = logging.getLogger(__name__)
hinter = hinting.get_hinter(__name__)


class CodeCoverage(analysis.Analysis):
    """A simple analysis that logs jumps, calls, and returns."""

    name = "code-coverage"
    description = ""
    version = "0.0.1"

    def run(self, machine) -> None:
        emulator = emulators.UnicornEmulator(machine.get_platform())
        coverage: typing.Dict[int, int] = {}

        for step in machine.step(emulator):
            cpu = step.get_cpu()
            pc = cpu.pc.get_content()
            if pc in coverage:
                coverage[pc] += 1
            else:
                coverage[pc] = 1

        hint = hinting.CoverageHint(message="Coverage for execution", coverage=coverage)
        hinter.info(hint)
