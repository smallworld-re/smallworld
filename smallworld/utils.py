import copy
import json
import logging
import sys
import typing

import pyhidra

from . import hinting, state

logger = logging.getLogger(__name__)


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


pyhidra_started = False


def setup_default_libc(
    elf_file: str, libc_func_names: typing.List[str], cpustate: state.CPU
) -> None:
    """Map some default libc models into the cpu state.

    Uses Ghdira to figure out entry points in PLT for libc fns and arranges for
    those in a user-provided list to be hooked using the default models in
    Smallworld.  Idea is you might not want all of them mapped and so you say
    just these for now.

    Arguments:
        elf_file: filename for program being analyzed (ghidra will look at its PLT entries)
        libc_func_names: list of names of libc functions
        cpustate: cpu state into which to map models
    """

    # not sure what happens if we start it twice...
    global pyhidra_started
    if pyhidra_started is False:
        pyhidra.start()
        pyhidra_started = True

    with pyhidra.open_program(elf_file) as flat_api:
        program = flat_api.getCurrentProgram()
        listing = program.getListing()

        # find plt section
        plt = None
        for block in program.getMemory().getBlocks():
            if "plt" in block.getName():
                plt = block

        # map all requested libc default models
        num_mapped = 0
        num_no_model = 0
        num_too_many_models = 0
        for func in listing.getFunctions(True):
            func_name = func.getName()
            entry = func.getEntryPoint()
            if plt.contains(entry) and func_name in libc_func_names:  # type: ignore
                # func is in plt and it is a function for which we want to use a default model
                int_entry = int(entry.getOffset())
                ml = state.models.get_models_by_name(
                    func_name, state.models.AMD64SystemVImplementedModel
                )
                # returns list of models. for now we hope there's either 1 or 0...
                if len(ml) == 1:
                    class_ = ml[0]
                    # class_ = getattr(state.models, cls_name)
                    cpustate.map(class_(int_entry))
                    logger.debug(
                        f"Added libc model for {func_name} entry {int_entry:x}"
                    )
                    num_mapped += 1
                elif len(ml) > 1:
                    logger.debug(
                        f"XXX There are {len(ml)} models for plt fn {func_name}... ignoring bc I dont know which to use"
                    )
                    num_too_many_models += 1
                else:
                    logger.debug(
                        f"As there is no default model for {func_name}, adding with null model, entry {int_entry:x}"
                    )
                    cpustate.map(state.models.AMD64SystemVNullModel(int_entry))
                    num_no_model += 1

        logger.info(
            f"Libc model mappings: {num_mapped} default, {num_no_model} no model, {num_too_many_models} too many models"
        )
