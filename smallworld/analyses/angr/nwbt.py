import angr

from .divergence import DivergenceExplorationMixin, DivergenceMemoryMixin
from .memtrack import TrackerMemoryMixin
from .model import ModelMemoryMixin
from .terminate import TerminationExplorationMixin
from .typedefs import TypeDefPlugin


class NWBTMemoryPlugin(
    DivergenceMemoryMixin,
    TrackerMemoryMixin,
    ModelMemoryMixin,
    angr.storage.DefaultMemory,
):
    pass


class NWBTExplorationTechnique(
    TerminationExplorationMixin,
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
