import abc
import typing
import logging

# logging re-exports
from logging import DEBUG  # noqa
from logging import INFO  # noqa
from logging import WARNING  # noqa
from logging import CRITICAL  # noqa


class Hint(metaclass=abc.ABCMeta):
    """Base class for all Hints.

    Arguments:
        message (str): A message for this Hint.
    """

    def __init__(self, message: str):
        self.message = message

    def __json__(self) -> dict:
        return {"type": self.__class__.__name__, "message": self.message}

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({repr(self.message)})"


class Hinter(logging.Logger):
    """A custom logger that only accepts Hints."""

    def _log(self, level, msg, *args, **kwargs):
        if not isinstance(msg, Hint):
            raise ValueError(f"{repr(msg)} is not a Hint")

        return super()._log(level, msg, *args, **kwargs)


root = Hinter(name="root", level=WARNING)
Hinter.root = typing.cast(logging.RootLogger, root)
Hinter.manager = logging.Manager(Hinter.root)
Hinter.manager.loggerClass = Hinter


def getHinter(name: typing.Optional[str] = None) -> Hinter:
    """Get a hinter with the given name.

    Arguments:
        name (str): The name of the hinter to get - if `None` this returns the
            root Hinter.

    Returns:
        A Hinter with the given name.
    """

    if not name or isinstance(name, str) and name == root.name:
        return root

    return typing.cast(Hinter, Hinter.manager.getLogger(name))
