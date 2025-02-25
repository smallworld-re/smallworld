import angr

from ...emulators import AngrEmulator
from ...emulators.angr.exploration import (
    BoundedExplorationMixin,
    TerminationExplorationMixin,
)
from ...emulators.angr.memory import TrackerMemoryMixin
from .detector import InputDetectionMemoryMixin


class InputDetectionMemoryPlugin(  # type: ignore[misc]
    TrackerMemoryMixin, InputDetectionMemoryMixin, angr.storage.DefaultMemory
):
    pass


class InputDetectionExplorationTechnique(
    TerminationExplorationMixin,
    BoundedExplorationMixin,
    angr.exploration_techniques.suggestions.Suggestions,
):
    pass


def configure_id_plugins(emu: AngrEmulator) -> None:
    preset = angr.SimState._presets["default"].copy()
    preset.add_default_plugin("sym_memory", InputDetectionMemoryPlugin)
    emu._plugin_preset = preset


def configure_id_strategy(emu: AngrEmulator) -> None:
    emu.mgr.use_technique(InputDetectionExplorationTechnique())
