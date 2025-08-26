from ....posix.libgen import Basename, Dirname
from ..systemv import AMD64SysVModel


class AMD64SysVBasename(Basename, AMD64SysVModel):
    pass


class AMD64SysVDirname(Dirname, AMD64SysVModel):
    pass


__all__ = [
    "AMD64SysVBasename",
    "AMD64SysVDirname",
]
