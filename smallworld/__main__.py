import logging
import argparse

from . import utils
from . import __title__
from . import __description__


LOGGING_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}


def main():
    parser = argparse.ArgumentParser(
        description="{}: {}".format(__title__, __description__),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-l",
        "--logging-level",
        choices=LOGGING_LEVELS,
        default="info",
        help="logging level",
    )

    arguments = parser.parse_args()

    utils.setup_logging(level=LOGGING_LEVELS[arguments.logging_level])


if __name__ == "__main__":
    main()
