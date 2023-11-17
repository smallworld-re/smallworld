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
