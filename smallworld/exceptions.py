class ConfigurationError(Exception):
    """Raised when there is a problem with configuration."""

    pass


class EmulationError(Exception):
    """Raised when the underlying emulator fails.

    Emulators should wrap known exceptions in this so we can differentiate
    between expected and unexpected failures.

    Arguments:
        exception: The original exception thrown.
    """

    def __init__(self, exception: Exception):
        self.exception = exception

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.exception})"


class AnalysisError(Exception):
    """Some kind of error in analysis."""

    def __init__(self, msg: str):
        self.msg = msg

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.msg})"


class AnalysisSetupError(AnalysisError):
    """Raised when an analysis run gets into trouble during setup."""

    pass


class AnalysisRunError(AnalysisError):
    """Raised when something goes wrong during an analysis."""

    pass


__all__ = [
    "ConfigurationError",
    "EmulationError",
    "AnalysisError",
    "AnalysisSetupError",
    "AnalysisRunError",
]
