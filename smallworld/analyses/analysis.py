import abc

from smallworld.hinting.hinting import Hinter

from .. import state, utils


class Analysis(utils.MetadataMixin):
    """An analysis that emits some information about some code, possibly to help with harnessing."""

    def __init__(self, hinter: Hinter, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.hinter = hinter

    @abc.abstractmethod
    def run(self, machine: state.Machine) -> None:
        """Run the analysis.

        This function **should not** modify the provided Machine. Instead, it
        should be coppied before modification.

        Arguments:
            machine: A machine state object on which this analysis should run.
        """

        pass


__all__ = ["Analysis"]
