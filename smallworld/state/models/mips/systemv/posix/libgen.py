from ....posix.libgen import Basename, Dirname
from ..systemv import MIPSSysVModel


class MIPSSysVBasename(Basename, MIPSSysVModel):
    pass


class MIPSSysVDirname(Dirname, MIPSSysVModel):
    pass


__all__ = [
    "MIPSSysVBasename",
    "MIPSSysVDirname",
]
