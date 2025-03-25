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


class Filter(utils.MetadataMixin):
    """Analyses that consume and sometimes produce additional hints.

    Filter analyses are analyses that consume some part of the hint
    stream and possibly emit new higher-level, synthetic hints. These
    analyses do not inspect machine state directly, they just react to
    hints from other analyses.

    """

    def __init__(self):
        self.listeners = []

    def listen(
        self,
        hint: typing.Type[hinting.Hint],
        method: typing.Callable[[hinting.Hint], None],
    ) -> None:
        """Register a listener for a particular hint type on the hint stream.

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


__all__ = ["Analysis", "Filter"]
