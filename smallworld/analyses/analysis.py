import abc
import logging
import typing

from .. import hinting, state, utils


class Analysis(utils.MetadataMixin):
    """An analysis that emits some information about some code, possibly to help with harnessing."""

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
