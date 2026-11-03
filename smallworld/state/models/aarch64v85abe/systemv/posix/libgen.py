from ....posix.libgen import Basename, Dirname
from ..systemv import AArch64V85ABESysVModel


class AArch64V85ABESysVBasename(Basename, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVDirname(Dirname, AArch64V85ABESysVModel):
    pass


__all__ = [
    "AArch64V85ABESysVBasename",
    "AArch64V85ABESysVDirname",
]
