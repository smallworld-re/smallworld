import typing


class Error(Exception):
    """Common base class for all exceptions."""


class ConfigurationError(Error):
    """Raised when there is a problem with configuration."""


class EmulationError(Error):
    """Raised when the underlying emulator fails.

    This wraps known exceptions thrown by an Emulator.

    Arguments:
        exception: The original exception thrown.
    """

    def __init__(self, exception: typing.Optional[Exception] = None):
        self.exception = exception

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.exception or ''})"


class AnalysisError(Error):
    """Some kind of error in analysis."""


__all__ = [
    "Error",
    "ConfigurationError",
    "EmulationError",
    "AnalysisError",
]
