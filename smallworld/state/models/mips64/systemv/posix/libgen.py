from ....posix.libgen import Basename, Dirname
from ..systemv import MIPS64SysVModel


class MIPS64SysVBasename(Basename, MIPS64SysVModel):
    pass


class MIPS64SysVDirname(Dirname, MIPS64SysVModel):
    pass


__all__ = [
    "MIPS64SysVBasename",
    "MIPS64SysVDirname",
]
