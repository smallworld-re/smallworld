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
    log = logging.getLogger("smallworld.memory")

    def __init__(self, **kwargs):
        self.log.debug(f"Memory plugin initialized.  kwargs: {kwargs}")
        super().__init__(**kwargs)


class NWBTExplorationTechnique(
    TerminationExplorationMixin,
    DivergenceExplorationMixin,
    angr.exploration_techniques.suggestions.Suggestions,
):
    log = logging.getLogger("smallworld.exploration")
