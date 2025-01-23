import typing

from ..emulators import AngrEmulator
from ..platforms import Platform
from ..state import Machine
from .analysis import Analysis


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

        for ip in self.trace:
            emulator.write_register_content("pc", ip)
            emulator.step()

        # TODO: What do we want to do after
        # TODO: Handle non-graceful exits
        emulator.state.registers.pp(print)
