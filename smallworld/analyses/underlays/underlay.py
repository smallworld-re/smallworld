import abc

from ...emulators import Emulator
from ..analysis import Analysis


class AnalysisUnderlay(Analysis):
    """Base class for execution underlays

    Some analyses are orthogonal to
    exactly how their program gets actuated.
    In those cases, the author can write the
    bulk of the analysis in an overlay,
    and pair that overlay with different underlays.
    """

    @property
    def emulator(self) -> Emulator:
        """The emulator to run
        Underlays need the overlay to define the emulator.
        """
        return self._emulator

    @emulator.setter
    def emulator(self, emu: Emulator):
        self._emulator = emu

    @abc.abstractmethod
    def execute(self) -> None:
        """Exercise the emulator"""
        raise NotImplementedError()
