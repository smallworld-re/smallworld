from importlib import metadata as __metadata

metadata = __metadata.metadata("smallworld")

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
    logging,
    platforms,
    state,
    models
)

__all__ = [
    "logging",
    "hinting",
    "platforms",
    "emulators",
    "state",
    "analyses",
    "exceptions",
    "extern",
    "models",
]
