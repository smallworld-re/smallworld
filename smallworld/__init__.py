from importlib import metadata as __metadata

metadata = __metadata.metadata("smallworld")

__title__ = metadata["name"]
__description__ = metadata["Summary"]
__author__ = metadata["Author"]
__version__ = metadata["version"]


from . import analyses, emulators, exceptions, extern, hinting, logging

__all__ = ["logging", "hinting", "emulators", "analyses", "exceptions", "extern"]
