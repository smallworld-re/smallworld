from ...exceptions import EmulationStop
from .underlay import AnalysisUnderlay


class BasicAnalysisUnderlay(AnalysisUnderlay):
    """Basic analysis underlay that steps until done"""

    def execute(self):
        try:
            while True:
                self.emulator.step()
        except EmulationStop:
            pass
