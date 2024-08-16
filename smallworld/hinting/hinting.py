import logging
import typing
from dataclasses import dataclass

# logging re-exports
from logging import WARNING

from .. import utils


@dataclass(frozen=True)
class Hint(utils.Serializable):
    """Base class for all Hints.

    Arguments:
        message: A message for this Hint.
    """

    message: str
    """A detailed description."""

    def to_dict(self) -> dict:
        """Convert this to a dict which can be trivially serialized."""

        return self.__dict__

    @classmethod
    def from_dict(cls, dict):
        """Load from a dictionary."""

        return cls(**dict)


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
        name: The name of the hinter to get - if `None` this returns the
            root Hinter.

    Returns:
        A Hinter with the given name.
    """

    if not name or isinstance(name, str) and name == root.name:
        return root

    return typing.cast(Hinter, Hinter.manager.getLogger(name))


__all__ = [
    "Hint",
    "root",
    "getHinter",
]
