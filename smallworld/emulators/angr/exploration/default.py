import angr

from .bounds import BoundedExplorationMixin
from .terminate import TerminationExplorationMixin


class DefaultExplorationTechnique(
    TerminationExplorationMixin,
    BoundedExplorationMixin,
    angr.exploration_techniques.suggestions.Suggestions,
):
    """Default exploration technique.

    Registers a few default-useful plugins for the SimulationManager.
    """

    pass
