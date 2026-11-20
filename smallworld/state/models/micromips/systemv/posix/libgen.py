from ....posix.libgen import Basename, Dirname
from ..systemv import MicroMIPSSysVModel


class MicroMIPSSysVBasename(Basename, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVDirname(Dirname, MicroMIPSSysVModel):
    pass


__all__ = [
    "MicroMIPSSysVBasename",
    "MicroMIPSSysVDirname",
]
