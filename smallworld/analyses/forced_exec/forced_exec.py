import logging
import typing

from ...emulators import AngrEmulator
from ...exceptions import EmulationStop
from ...platforms import Platform
from ...state import Machine
from ..underlays import AnalysisUnderlay

log = logging.getLogger(__name__)


class ForcedExecutionUnderlay(AnalysisUnderlay):
    """Forced execution analysis underlay

    This allows you to emulate arbitrary program slices
    by forcing the emulator to visit specific instructions,
    ignoring the normal program control flow.

    This isn't a complete analysis;
    instead, it's a dummy base class that makes it easy
    to support forced execution mode by implementing
    the complex logic as an overlay,
    and building the actual analysis as a combination
    of overlay and underlay.
    See field detection to see what I mean.

    NOTE: This is not compatible with all architectures.
    The architecture needs to support single-stepping;
    delay slot architectures such as MIPS can't
    be single-stepped by angr.

    Arguments:
        trace:      The list of program counter addresses you want to visit

    """

    def __init__(self, trace: typing.List[typing.Dict[str, int]]):
        self.trace: typing.List[typing.Dict[str, int]] = trace

    def execute(self):
        try:
            for regs in self.trace:
                for reg, val in regs.items():
                    self.emulator.write_register_content(reg, val)
                self.emulator.step()
        except EmulationStop:
            pass


class ForcedExecution(ForcedExecutionUnderlay):
    """Forced execution using angr

    This allows you to emulate arbitrary program slices
    by forcing the emulator to visit specific instructions,
    ignoring the normal program control flow.

    NOTE: This is not compatible with all architectures.
    The architecture needs to support single-stepping;
    delay slot architectures such as MIPS can't
    be single-stepped by angr.

    Arguments:
        platform:   The platform you want to emulate
        trace:      The list of program counter addresses you want to visit
    """

    name = "forced-execution"
    description = "Forced execution using angr"
    version = "0.0.1"

    def __init__(self, platform: Platform, trace: typing.List[typing.Dict[str, int]]):
        super().__init__(trace)
        self.platform: Platform = platform
        self.emulator = AngrEmulator(platform)
        self.emulator.enable_linear()

    def run(self, machine: Machine):
        emulator = self.emulator
        if not isinstance(emulator, AngrEmulator):
            raise TypeError("Impossible!")
        machine.apply(emulator)
        emulator.initialize()
        self.execute()
        for s in emulator.mgr.active:
            log.info(s.solver.constraints)
            s.registers.pp(log.info)
