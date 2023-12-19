import json
import logging
import sys
import typing
from dataclasses import asdict, dataclass

# logging re-exports
from logging import CRITICAL  # noqa
from logging import DEBUG  # noqa
from logging import INFO  # noqa
from logging import WARNING  # noqa


class HintJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Hint):
            d = asdict(o)
            d["hint_type"] = o.__class__.__name__
            return d
        return super().default(o)


class HintJSONDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, dict):
        if "hint_type" in dict:
            cls = getattr(sys.modules[__name__], dict["hint_type"])
            del dict["hint_type"]
            return cls(**dict)
        return dict


@dataclass(frozen=True)
class Hint:
    """Base class for all Hints.

    Arguments:
        message (str): A message for this Hint.
    """

    message: str


@dataclass(frozen=True)
class UnderSpecifiedValueHint(Hint):
    """Super class for UnderSpecified Value Hints"""

    pass


@dataclass(frozen=True)
class UnderSpecifiedRegisterHint(UnderSpecifiedValueHint):
    """Represents a register whose value can't be fully determined from the environment.

    Arguments:
        register (string): The register in question
    """

    register: str


@dataclass(frozen=True)
class UnderSpecifiedMemoryHint(UnderSpecifiedValueHint):
    """Represents a memory range whose value can't be fully determined from the environment.

    Arguments:
        address (int): The address of the beginning of the range
        size (int): The size of the range
    """

    address: int
    size: int


@dataclass(frozen=True)
class TypeHint(Hint):
    """Super class for Type Hints"""

    pass


@dataclass(frozen=True)
class RegisterPointerHint(TypeHint):
    """Signal that a register is probably a pointer.

    Arguments:
        register (string): The register in question
    """

    register: str


@dataclass(frozen=True)
class RegisterPointsToHint(RegisterPointerHint):
    """Signal that a register is probably a pointer and points to a type.

    Arguments:
        type (string): The type in question
    """

    type: str


@dataclass(frozen=True)
class MemoryPointerHint(TypeHint):
    """Signal that a memory address is probably a pointer.

    Arguments:
       address (int): The address in question
    """

    address: int


@dataclass(frozen=True)
class MemoryPointsToHint(RegisterPointerHint):
    """Signal that a memory address is probably a pointer and points to a type.

    Arguments:
        type (string): The type in question
    """

    type: str


@dataclass(frozen=True)
class StructureHint(TypeHint):
    """Signals the probable layout of a struct

    Arguments:
        layout (dict[int, str]): A dictionary of offset to type
    """

    layout: typing.Dict[int, str]


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
