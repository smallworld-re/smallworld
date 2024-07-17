import angr

from .exploration import DefaultExplorationTechnique
from .memory import DefaultMemoryPlugin
from .scratch import ExpandedScratchPlugin


def configure_default_plugins(emu):
    preset = angr.SimState._presets["default"]
    preset.add_default_plugin("sym_memory", DefaultMemoryPlugin)
    preset.add_default_plugin("scratch", ExpandedScratchPlugin)


def configure_default_strategy(emu):
    emu.mgr.use_technique(DefaultExplorationTechnique())
