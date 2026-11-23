from ....posix.libgen import Basename, Dirname
from ..systemv import SPARC32SysVModel


class SPARC32SysVBasename(Basename, SPARC32SysVModel):
    pass


class SPARC32SysVDirname(Dirname, SPARC32SysVModel):
    pass


__all__ = [
    "SPARC32SysVBasename",
    "SPARC32SysVDirname",
]
