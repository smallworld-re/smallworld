from ....posix.libgen import Basename, Dirname
from ..systemv import AArch64BESysVModel


class AArch64BESysVBasename(Basename, AArch64BESysVModel):
    pass


class AArch64BESysVDirname(Dirname, AArch64BESysVModel):
    pass


__all__ = [
    "AArch64BESysVBasename",
    "AArch64BESysVDirname",
]
