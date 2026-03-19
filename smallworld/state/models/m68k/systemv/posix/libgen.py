from ....posix.libgen import Basename, Dirname
from ..systemv import M68KSysVModel


class M68KSysVBasename(Basename, M68KSysVModel):
    pass


class M68KSysVDirname(Dirname, M68KSysVModel):
    pass


__all__ = [
    "M68KSysVBasename",
    "M68KSysVDirname",
]
