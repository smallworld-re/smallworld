import copy
import json
import logging
import sys
import typing
from dataclasses import dataclass

"""
Will this appear in docs?


"""

# logging re-exports
from logging import WARNING

from .. import logging as internal_logging


class Serializable:
    """Base class for serialization support.

    Descendants should implement the methods below to allow automatic
    serialization/deserialization using the JSON encoder/decoder classes below.
    """

    def to_dict(self) -> dict:
        raise NotImplementedError()

    @classmethod
    def from_dict(cls, dict):
        raise NotImplementedError()


@dataclass(frozen=True)
class Hint(Serializable):
    """Base class for all Hints.

    Arguments:
        message: A message for this Hint.
    """

    message: str
    """A detailed description."""

    def to_dict(self) -> dict:
        """Convert to a dictionary which can be trivially serialized.

        Returns:
            A dictionary containing the hint.
        """

        return self.__dict__

    @classmethod
    def from_dict(cls, dict):
        """Load from a dictionary.

        Arguments:
            dict: Dictionary from which to construct the hint.

        Returns:
            The constructed hint.
        """

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


def get_hinter(name: typing.Optional[str] = None) -> Hinter:
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


class SerializableJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Serializable):
            d = o.to_dict()
            d["class"] = f"{o.__class__.__module__}.{o.__class__.__name__}"

            return d
        return super().default(o)


class SerializableJSONDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, dict):
        if "class" in dict:
            module, name = dict["class"].rsplit(".", 1)
            cls = getattr(sys.modules[module], name)
            del dict["class"]

            return cls.from_dict(dict)
        return dict


class JSONFormatter(logging.Formatter):
    """A custom JSON formatter for json-serializable messages.

    Arguments:
        keys (dict): A dictionary mapping json keys to their logging format
            strings.
    """

    def __init__(self, *args, keys=None, **kwargs):
        super().__init__(*args, **kwargs)

        keys = keys or {}
        self.keys = {}
        for name, fmt in keys.items():
            self.keys[name] = logging.Formatter(fmt)

    def format(self, record):
        formatted = {}

        for key, formatter in self.keys.items():
            formatted[key] = formatter.format(record)

        formatted["content"] = record.msg

        hint, record.msg = record.msg, None
        modified = copy.deepcopy(record)
        record.msg = hint

        modified.msg = json.dumps(formatted, cls=SerializableJSONEncoder)

        return super().format(modified)


def setup_hinting(
    level: int = logging.INFO,
    verbose: bool = False,
    colors: bool = True,
    stream: bool = True,
    file: typing.Optional[str] = None,
) -> None:
    """Set up hint handling.

    Note:
        This should only be called once.

    Arguments:
        level: Hinting level (from `hinting` module).
        verbose: Enable verbose hinting mode.
        colors: Enable hinting colors (if supported).
        stream: Enable stream logging.
        file: If provided, enable file logging to the path provided.
    """

    if verbose:
        keys = {
            "time": "%(asctime)s",
            "level": "%(levelname)s",
            "source": "%(name)s",
        }
    else:
        keys = {}

    root = get_hinter()
    root.setLevel(level)

    if stream:
        format = "[%(levelchar)s] %(message)s"

        if colors and sys.stderr.isatty():
            format = f"%(levelcolor)s{format}{internal_logging.ColorLevelFilter.END}"

        formatter = JSONFormatter(format, keys=keys)

        handler: logging.Handler = logging.StreamHandler()
        handler.setLevel(level)
        handler.addFilter(internal_logging.CharacterLevelFilter())
        handler.addFilter(internal_logging.ColorLevelFilter())
        handler.setFormatter(formatter)

        root.addHandler(handler)

    if file:
        formatter = JSONFormatter("%(message)s", keys=keys)
        handler = logging.FileHandler(file, mode="w")
        handler.setFormatter(formatter)
        root.addHandler(handler)


__all__ = ["Hint", "Serializable", "root", "get_hinter", "setup_hinting"]
