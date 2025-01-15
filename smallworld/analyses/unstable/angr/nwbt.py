import angr

from ....emulators.angr.exploration import (
    BoundedExplorationMixin,
    TerminationExplorationMixin,
)
from ....emulators.angr.memory import TrackerMemoryMixin
from .divergence import DivergenceExplorationMixin, DivergenceMemoryMixin
from .model import ModelMemoryMixin
from .typedefs import TypeDefPlugin


class NWBTMemoryPlugin(  # type: ignore[misc]
    DivergenceMemoryMixin,
    TrackerMemoryMixin,
    ModelMemoryMixin,
    angr.storage.DefaultMemory,
):
    pass


class NWBTExplorationTechnique(
    TerminationExplorationMixin,
    BoundedExplorationMixin,
    DivergenceExplorationMixin,
    angr.exploration_techniques.suggestions.Suggestions,
):
    pass


def configure_nwbt_plugins(emu):
    """Configure NWBT analysis plugins.

    This creates a new plugin preset that overrides
    angr's default symbolic memory plugin.
    This preset is passed to the entry state constructor,
    and can't be changed afterward.
    Thus, this needs to get called in a preinit callback.
    """
    preset = angr.SimState._presets["default"].copy()
    preset.add_default_plugin("sym_memory", NWBTMemoryPlugin)
    preset.add_default_plugin("typedefs", TypeDefPlugin)
    emu._plugin_preset = preset


def configure_nwbt_strategy(emu):
    """Configure NWBT analysis strategies

    This overrides the default angr exploration strategy.
    This needs to access the instantiated exploration manager,
    so it needs to get called in an init callback.
    """
    emu.mgr.use_technique(NWBTExplorationTechnique())
    # angr bug: states don't inherit plugin presets.
    #
    # Normally, they copy all plugins from their parents.
    # If you define a custom plugin and don't touch it,
    # it never gets initialized, and won't get inherited.
    #
    # If you try to touch that plugin on a successor,
    # it can't be initialized, since it doesn't have
    # your custom preset.
    emu.state.get_plugin("typedefs")
