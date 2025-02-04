class Error(Exception):
    """Common base class for all exceptions."""


class ConfigurationError(Error):
    """Raised when there is a problem with configuration."""

    pass


class EmulationError(Error):
    """Raised when emulation fails."""

    pass


class EmulationStop(EmulationError):
    """Base class for all emulation stopping exceptions."""

    pass


class EmulationBounds(EmulationStop):
    """Raised when execution goes out of bounds."""

    pass


class EmulationExitpoint(EmulationStop):
    """Raised when execution hits an exit point."""

    pass


class UnsupportedRegisterError(EmulationError):
    """Raised if you ask for a register unsupported by the emulator"""

    pass


class SymbolicValueError(EmulationError):
    """Raised if you try to collapse a symbolic value to a concrete one"""

    pass


class UnsatError(EmulationError):
    """Raised if a symbolic expression is unsatisfiable given constraints"""

    pass


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
    "EmulationStop",
    "EmulationBounds",
    "EmulationExitpoint",
    "EmulationException",
    "SymbolicValueError",
    "UnsatError",
    "UnsupportedRegisterError",
    "AnalysisError",
]
