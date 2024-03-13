import abc
import logging
import typing

from .. import hinting, state

logger = logging.getLogger(__name__)
hinter = hinting.getHinter(__name__)


class Metadata(metaclass=abc.ABCMeta):
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


class Analysis(Metadata):
    """The base class for all analyses."""

    @abc.abstractmethod
    def run(self, state: state.CPU) -> None:
        """Actually run the analysis.

        This function **should not** modify the provided State - instead, it
        should be coppied before modification.

        Arguments:
            state: A state class on which this analysis should run.
        """

        pass


class Filter(Metadata):
    """The base class for filter analyses.

    Filter analyses are analyses that consume some part of the hint stream and
    possibly emit additional hints. These analyses do not run any analysis on
    the system state, they just react to hints from other analyses.
    """

    def __init__(self):
        self.listeners = []

    def listen(
        self,
        hint: typing.Type[hinting.Hint],
        method: typing.Callable[[hinting.Hint], None],
    ):
        """Register a listener on the hint stream.

        Arguments:
            hint: A hint type that should trigger this listener. Note: All
                subclasses `hint` will trigger the listener.
            method: The method to call when the given hint type is observed.
        """

        class Handler(logging.Handler):
            def emit(self, record):
                method(record.msg)

        handler = Handler()
        handler.setLevel(logging.DEBUG)
        handler.addFilter(hinting.HintSubclassFilter(hint))
        hinting.root.addHandler(handler)

        self.listeners.append(handler)

    @abc.abstractmethod
    def activate(self) -> None:
        """Activate this filter.

        Implementations should make necessary calls to `listen()` here to
        register hint listener functions. They will be unregistered
        automatically on destruction or manual call to `deactivate()`.
        """

        pass

    def deactivate(self) -> None:
        """Deactivate this filter.

        This is done automatically on destruction of this object - you likely
        shouldn't need to call this manually.
        """

        for handler in self.listeners:
            hinting.root.removeHandler(handler)

    def __del__(self):
        self.deactivate()
