from importlib import metadata as __metadata

metadata = __metadata.metadata("smallworld-re")

__title__ = metadata["name"]
__description__ = metadata["Summary"]
__author__ = metadata["Author"]
__version__ = metadata["version"]


from . import (
    analyses,
    emulators,
    exceptions,
    extern,
    hinting,
    instructions,
    logging,
    platforms,
    state,
)
from .helpers import *  # noqa: F401, F403
from .helpers import __all__ as __helpers__

__all__ = __helpers__ + [
    "analyses",
    "emulators",
    "exceptions",
    "extern",
    "hinting",
    "instructions",
    "logging",
    "platforms",
    "state",
]
