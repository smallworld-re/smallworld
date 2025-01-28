import logging
import typing

from ..emulators import AngrEmulator
from ..exceptions import EmulationStop
from ..platforms import Platform
from ..state import Machine
from .analysis import Analysis

log = logging.getLogger(__name__)


class ForcedExecution(Analysis):
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
                emulator.write_register_content("eip", ip)
                emulator.state.registers.pp(log.info)
                emulator.step()
        except EmulationStop:
            for s in emulator.mgr.active:
                log.info(s.solver.constraints)
                emulator.state.registers.pp(log.info)
