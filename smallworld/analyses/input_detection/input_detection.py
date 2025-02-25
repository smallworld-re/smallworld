from ...emulators import AngrEmulator
from ...state import Machine
from ..analysis import Analysis
from .plugins import configure_id_plugins, configure_id_strategy


class InputDetection(Analysis):
    """Analysis that detects uninitialized inputs"""

    name = "input-detection"
    version = "0.0"
    description = "Detect reads from uninitialized memory and registers"

    def run(self, machine: Machine) -> None:
        emulator = AngrEmulator(
            machine.get_platform(),
            preinit=configure_id_plugins,
            init=configure_id_strategy,
        )
        machine.apply(emulator)
        emulator.run()
