import angr
import logging
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
    l = logging.getLogger("smallworld.memory")

    def __init__(self, **kwargs):
        self.l.debug(f"Memory plugin initialized.  kwargs: {kwargs}")
        super().__init__(**kwargs)


class NWBTExplorationTechnique(
    TerminationExplorationMixin,
    DivergenceExplorationMixin,
    angr.exploration_techniques.suggestions.Suggestions,
):
    l = logging.getLogger("smallworld.exploration")
