import copy
import logging

from .. import emulators, hinting, state
from . import analysis

logger = logging.getLogger(__name__)
hinter = hinting.getHinter(__name__)


class CodeReachable(analysis.Analysis):
    """A simple analysis that logs what code is reachable by symbolic execution."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    name = "code-reachable"
    description = ""
    version = "0.0.1"

    def run(self, state: state.CPU) -> None:
        cpu = copy.deepcopy(state)
        emulator = emulators.AngrEmulator()
        cpu.apply(emulator)

        try:
            while emulator.step():
                if emulator.mgr:
                    for s in emulator.mgr.active:
                        pc = s._ip.concrete_value
                        hint = hinting.ReachableCodeHint(
                            message=f"Address {hex(pc)} is reachable via symbolic execution",
                            address=pc,
                        )
                        hinter.info(hint)
        except emulators.angr.PathTerminationSignal:
            return
