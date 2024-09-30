from ... import exceptions


class SymbolicValueError(exceptions.EmulationError):
    """Exception indicating a value cannot be returned because it is symbolic"""

    pass


class PathTerminationSignal:
    """Exception allowing an analysis to terminate an execution path."""

    pass
