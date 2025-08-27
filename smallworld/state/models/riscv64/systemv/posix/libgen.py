from ....posix.libgen import Basename, Dirname
from ..systemv import RiscV64SysVModel


class RiscV64SysVBasename(Basename, RiscV64SysVModel):
    pass


class RiscV64SysVDirname(Dirname, RiscV64SysVModel):
    pass


__all__ = [
    "RiscV64SysVBasename",
    "RiscV64SysVDirname",
]
