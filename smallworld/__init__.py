from __future__ import annotations

import pathlib
import re
from importlib import metadata as __metadata


def _metadata_from_source_tree() -> dict[str, str]:
    """Fallback metadata for source-tree imports before the package is installed."""

    defaults = {
        "name": "smallworld-re",
        "Summary": "An emulation stack tracking library",
        "Author": "MIT Lincoln Laboratory",
        "version": "0+local",
    }
    pyproject = pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml"
    if not pyproject.exists():
        return defaults
    content = pyproject.read_text()
    patterns = {
        "name": r'^name = "([^"]+)"$',
        "Summary": r'^description = "([^"]+)"$',
        "version": r'^version = "([^"]+)"$',
    }
    result = dict(defaults)
    for key, pattern in patterns.items():
        match = re.search(pattern, content, re.MULTILINE)
        if match:
            result[key] = match.group(1)
    return result


try:
    metadata = __metadata.metadata("smallworld-re")
except __metadata.PackageNotFoundError:
    metadata = _metadata_from_source_tree()

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
