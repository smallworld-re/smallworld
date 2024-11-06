from ... import exceptions


class PathTerminationSignal(exceptions.unstable.AnalysisSignal):
    """Exception allowing an analysis to terminate an execution path."""

    pass
