import logging
import sys


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


def setup_logging(
    level: int = logging.INFO,
    verbose: bool = False,
    colors: bool = True,
    clear: bool = True,
) -> None:
    """Setup log handling.

    Note: this should only be called once.

    Arguments:
        level: Logging level (from `logging` module).
        verbose: Enable verbose logging mode.
        colors: Enable logging colors (if supported).
        clear: Remove all other handlers from the root logger.
    """

    if verbose:
        format = "[%(asctime)s %(levelname)-7s|%(name)s]: %(message)s"
    else:
        format = "[%(levelchar)s] %(message)s"

    if colors and sys.stderr.isatty():
        format = f"%(levelcolor)s{format}{ColorLevelFilter.END}"

    root = logging.getLogger()
    root.setLevel(level)

    if clear:
        handlers = list(root.handlers)
        for handler in handlers:
            root.removeHandler(handler)

    formatter = logging.Formatter(format)

    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.addFilter(CharacterLevelFilter())
    handler.addFilter(ColorLevelFilter())

    handler.setFormatter(formatter)

    root.addHandler(handler)


__all__ = ["setup_logging"]
