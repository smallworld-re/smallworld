import copy
import json
import logging
import sys
import typing

from . import analyses, emulators, hinting, state


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

        modified = copy.deepcopy(record)
        modified.msg = json.dumps(formatted, cls=hinting.HintJSONEncoder)

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


T = typing.TypeVar("T", bound=state.CPU)


def emulate(state: T) -> T:
    """Emulate execution of some code.

    Arguments:
        state: A state class from which emulation should begin.

    Returns:
        The final state of the system.
    """

    # only support Unicorn for now
    emu = emulators.UnicornEmulator(state.arch, state.mode)

    state.apply(emu)

    emu.run()

    state = copy.deepcopy(state)
    state.load(emu)

    return state


def analyze(state: T) -> None:
    """Run all available analyses on some code.

    All analyses are run with default parameters.

    Arguments:
        state: A state class from which emulation should begin.
    """

    for name in analyses.__all__:
        module: typing.Type = getattr(analyses, name)
        if isinstance(module, analyses.Filter):
            module().activate()

    for name in analyses.__all__:
        module = getattr(analyses, name)
        if isinstance(module, analyses.Analysis):
            module().run(state)
