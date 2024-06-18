from importlib import metadata as __metadata

metadata = __metadata.metadata("smallworld")

__title__ = metadata["name"]
__description__ = metadata["Summary"]
__author__ = metadata["Author"]
__version__ = metadata["version"]

from . import analyses, cpus, emulators, exceptions, hinting, initializers, state
from .helpers import (  # noqa: F401
    analyze,
    emulate,
    fuzz,
    setup_default_libc,
    setup_section,
)
from .utils import setup_hinting, setup_logging

__all__ = [
    "analyses",
    "cpus",
    "emulators",
    "exceptions",
    "hinting",
    "initializers",
    "state",
    "setup_hinting",
    "setup_logging",
    "analyze",
    "emulate",
    "fuzz",
]
