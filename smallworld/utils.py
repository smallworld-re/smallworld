import copy
import inspect
import json
import logging
import sys
import typing

from . import hinting


class CharacterLevelFilter(logging.Filter):
    """Adds logging level as a single character for formatting."""

    CHARACTERS = {
        logging.DEBUG: "-",
        logging.INFO: "+",
        logging.WARNING: "!",
        logging.ERROR: "*",
        logging.CRITICAL: "#",
    }

    def filter(self, record):
        record.levelchar = self.CHARACTERS.get(record.levelno, " ")
        return True


class ColorLevelFilter(logging.Filter):
    """Adds logging level as a color for formatting."""

    WHITE_DIM = "\x1b[37;2m"
    WHITE = "\x1b[37m"
    YELLOW = "\x1b[33m"
    RED = "\x1b[31m"
    RED_BOLD = "\x1b[31;1m"
    END = "\x1b[0m"
    NULL = END

    COLORS = {
        logging.DEBUG: WHITE_DIM,
        logging.INFO: WHITE,
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
        logging.CRITICAL: RED_BOLD,
    }

    def filter(self, record):
        record.levelcolor = self.COLORS.get(record.levelno, self.NULL)
        return True


class Serializable:
    """Base class for serialization support.

    Descendants should implement the methods below to allow automatic
    serialization/deserialization using the JSON encoder/decoder classes below.
    """

    def to_json(self) -> dict:
        raise NotImplementedError()

    @classmethod
    def from_json(cls, dict):
        raise NotImplementedError()


class SerializableJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Serializable):
            d = o.to_json()
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

            return cls.from_json(dict)
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

        # inefficient copy to aovid ctypes pickling issues
        hint, record.msg = record.msg, None
        modified = copy.deepcopy(record)
        record.msg = hint

        modified.msg = json.dumps(formatted, cls=SerializableJSONEncoder)

        return super().format(modified)


def setup_logging(
    level: int = logging.INFO,
    verbose: bool = False,
    colors: bool = True,
    clear_handlers: bool = True,
) -> None:
    """Setup log handling.

    Note: this should only be called once.

    Arguments:
        level: Logging level (from `logging` module).
        verbose: Enable verbose logging mode.
        colors: Enable logging colors (if supported).
    """

    if verbose:
        format = "[%(asctime)s %(levelname)-7s|%(name)s]: %(message)s"
    else:
        format = "[%(levelchar)s] %(message)s"

    if colors and sys.stderr.isatty():
        format = f"%(levelcolor)s{format}{ColorLevelFilter.END}"

    root = logging.getLogger()
    root.setLevel(level)

    if clear_handlers:
        # Clear existing handlers.
        # Some libraries (angr) install their own handlers.
        # This results in multiple copies of each message.
        handlers = list(root.handlers)
        for old_handler in handlers:
            root.removeHandler(old_handler)

    formatter = logging.Formatter(format)

    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.addFilter(CharacterLevelFilter())
    handler.addFilter(ColorLevelFilter())

    handler.setFormatter(formatter)

    root.addHandler(handler)


def setup_hinting(
    level: int = logging.INFO,
    verbose: bool = False,
    colors: bool = True,
    stream: bool = True,
    file: typing.Optional[str] = None,
) -> None:
    """Setup hint handling.

    Note: this should only be called once.

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

    root = hinting.getHinter()
    root.setLevel(level)

    if stream:
        format = "[%(levelchar)s] %(message)s"

        if colors and sys.stderr.isatty():
            format = f"%(levelcolor)s{format}{ColorLevelFilter.END}"

        formatter = JSONFormatter(format, keys=keys)

        handler: logging.Handler = logging.StreamHandler()
        handler.setLevel(level)
        handler.addFilter(CharacterLevelFilter())
        handler.addFilter(ColorLevelFilter())
        handler.setFormatter(formatter)

        root.addHandler(handler)

    if file:
        formatter = JSONFormatter("%(message)s", keys=keys)

        handler = logging.FileHandler(file)
        handler.setLevel(level)
        handler.setFormatter(formatter)

        root.addHandler(handler)


def find_subclass(
    cls: typing.Type[typing.Any],
    check: typing.Callable[[typing.Type[typing.Any]], bool],
    *args,
    **kwargs,
):
    """Find and instantiate a subclass for dependency injection

    This pattern involves finding an implementation by sematic criteria,
    rather than explicity encoding a reference to it.

    This makes for nice modular code, since the invoker
    doesn't need to get updated every time a new module is added.

    Arguments:
        cls: The class representing the interface to search
        check: Callable for testing the desired criteria
        args: Any positional/variadic args to pass to the initializer
        kwargs: Any keyword arguments to pass to the initializer

    Returns: An instance of a subclass of cls matching the criteria from check

    Raises:
        ValueError: If no subclass of cls matches the criteria
    """
    class_stack: typing.List[typing.Type[typing.Any]] = [cls]
    while len(class_stack) > 0:
        impl: typing.Type[typing.Any] = class_stack.pop(-1)

        if inspect.isabstract(impl):
            print(f"{impl} is abstract")
        if not inspect.isabstract(impl) and check(impl):
            return impl(*args, **kwargs)
        # __subclasses__ is not transitive;
        # need to call this on each sublclass to do a full traversal.
        class_stack.extend(impl.__subclasses__())

    raise ValueError(f"No instance of {cls} matching criteria")
