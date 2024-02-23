import abc
import logging

from .. import hinting, state

logger = logging.getLogger(__name__)
hinter = hinting.getHinter(__name__)


class Analysis:
    """The base class for all analyses."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """The name of this analysis.

        Names should be kebab-case, all lowercase, no whitespace for proper
        formatting.
        """
        pass

    @property
    @abc.abstractmethod
    def description(self) -> str:
        """A description of this analysis.

        Descriptions should be a single sentence, lowercase, with no final
        punctuation for proper formatting.
        """

        return ""

    @property
    @abc.abstractmethod
    def version(self) -> str:
        """The version string for this analysis.

        We recommend using `Semantic Versioning`_

        .. _Semantic Versioning:
            https://semver.org/
        """

        return ""

    @abc.abstractmethod
    def run(self, state: state.CPU) -> None:
        """Actually run the analysis.

        This function **should not** modify the provided State - instead, it
        should be coppied before modification.

        Arguments:
            state: A state class on which this analysis should run.
        """

        pass
