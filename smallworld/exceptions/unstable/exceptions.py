from .. import exceptions


class UnicornEmulationError(exceptions.EmulationError):
    def __init__(self, exception: Exception, pc: int, data: dict):
        self.exception = exception
        self.pc = pc
        self.data = data

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}({self.exception}, {hex(self.pc)}, {self.data})"
        )


class AnalysisSetupError(exceptions.AnalysisError):
    """Raised when an analysis run gets into trouble during setup."""


class AnalysisRunError(exceptions.AnalysisError):
    """Raised when something goes wrong during an analysis."""


class AnalysisSignal(exceptions.Error):
    """Raised to signal a non-fatal exception during an analysis."""
