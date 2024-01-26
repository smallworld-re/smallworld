"""Custom named exceptions are defined here."""


class ConfigurationError(Exception):
    pass


class EmulationError(Exception):
    """Thrown when the underlying emulator fails.

    Executors should wrap known exceptions in this so we can differentiate
    between expected and unexpected failures.

    Arguments:
        exception (Exception): The original exception thrown.
    """

    def __init__(self, exception: Exception):
        self.exception = exception

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.exception})"


class AnalysisError(Exception):
    """Some kind of error in analysis.

    Arguments:
        message (string): A description of what went wrong
    """

    def __init__(self, msg: str):
        self.msg = msg

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.msg})"


class AnalysisSetupError(AnalysisError):
    """Thrown when an analysis run gets into trouble during setup, i.e.
    before it even begins

    Arguments:
        message (string): A description of what went wrong
    """

    pass


class AnalysisRunError(Exception):
    """Thrown when something goes wrong during an analysis.

    Arguments:
        message (string): A description of what went wrong
    """

    pass
