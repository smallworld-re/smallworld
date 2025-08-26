from ....posix.libgen import Basename, Dirname
from ..systemv import I386SysVModel


class I386SysVBasename(Basename, I386SysVModel):
    pass


class I386SysVDirname(Dirname, I386SysVModel):
    pass


__all__ = [
    "I386SysVBasename",
    "I386SysVDirname",
]
