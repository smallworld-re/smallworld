class Error(Exception):
    """Common base class for all exceptions."""


class ConfigurationError(Error):
    """Raised when there is a problem with configuration."""


class EmulationError(Error):
    """Raised when emulation fails."""


class EmulationBounds(EmulationError):
    """Raised when execution goes out of bounds."""


class EmulationExitpoint(EmulationError):
    """Raised when execution hits an exit point."""


class EmulationException(EmulationError):
    """Raised when the underlying emulator fails.

    This wraps known exceptions thrown by an Emulator.

    Arguments:
        exception: The original exception thrown.
    """

    def __init__(self, exception: Exception):
        self.exception = exception

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.exception})"


class AnalysisError(Error):
    """Some kind of error in analysis."""


__all__ = [
    "Error",
    "ConfigurationError",
    "EmulationError",
    "EmulationBounds",
    "EmulationExitpoint",
    "EmulationException",
    "AnalysisError",
]
