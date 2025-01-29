import logging
import typing

from ...emulators import AngrEmulator
from ...exceptions import EmulationStop
from ...platforms import Platform
from ...state import Machine
from ..analysis import Analysis

log = logging.getLogger(__name__)


class ForcedExecution(Analysis):
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

    def __init__(self, platform: Platform, trace: typing.List[int]):
        self.trace: typing.List[int] = trace
        self.platform: Platform = platform

    def run(self, machine: Machine):
        emulator = AngrEmulator(self.platform)
        emulator.enable_linear()
        machine.apply(emulator)
        emulator.initialize()
        try:
            for ip in self.trace:
                emulator.write_register_content("pc", ip)
                emulator.state.registers.pp(log.info)
                emulator.step()
        except EmulationStop:
            for s in emulator.mgr.active:
                log.info(s.solver.constraints)
                emulator.state.registers.pp(log.info)
