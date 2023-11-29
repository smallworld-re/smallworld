import angr
from .divergence import DivergenceMemoryMixin, DivergenceExplorationMixin
from .memtrack import TrackerMemoryMixin
from .model import ModelMemoryMixin
from .terminate import TerminationExplorationMixin


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
