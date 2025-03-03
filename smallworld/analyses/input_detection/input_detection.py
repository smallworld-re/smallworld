from ...emulators import AngrEmulator
from ...state import Machine
from ..analysis import Analysis
from .detector import InputDetectionMemoryMixin
from .plugins import configure_id_plugins, configure_id_strategy


class InputDetection(Analysis):
    """Analysis that detects uninitialized inputs"""

    name = "input-detection"
    version = "0.0"
    description = "Detect reads from uninitialized memory and registers"

    def __init__(self, halt_at_first_hint: bool = False):
        self.halt_at_first_hint = halt_at_first_hint

    def run(self, machine: Machine) -> None:
        InputDetectionMemoryMixin.halt_at_first_hint = self.halt_at_first_hint

        emulator = AngrEmulator(
            machine.get_platform(),
            preinit=configure_id_plugins,
            init=configure_id_strategy,
        )
        machine.apply(emulator)
        emulator.run()
