import copy
import logging

from .. import emulators, hinting, state
from . import analysis

logger = logging.getLogger(__name__)
hinter = hinting.get_hinter(__name__)


class CodeReachable(analysis.Analysis):
    """A simple analysis that logs what code is reachable by symbolic execution."""

    def __init__(self, max_steps=500, **kwargs):
        self.steps_left = max_steps
        super().__init__(**kwargs)

    name = "code-reachable"
    description = ""
    version = "0.0.1"

    def run(self, state: state.CPU) -> None:
        cpu = copy.deepcopy(state)
        emulator = emulators.AngrEmulator(state.arch, state.mode, state.byteorder)
        cpu.apply(emulator)

        try:
            while (
                self.steps_left is None or self.steps_left > 0
            ) and not emulator.step():
                if emulator.mgr:
                    for s in emulator.mgr.active:
                        pc = s._ip.concrete_value
                        hint = hinting.ReachableCodeHint(
                            message=f"Address {hex(pc)} is reachable via symbolic execution",
                            address=pc,
                        )
                        hinter.info(hint)
                if self.steps_left is not None:
                    self.steps_left -= 1
        except emulators.angr.PathTerminationSignal:
            return
