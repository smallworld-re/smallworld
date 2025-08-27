from ....posix.libgen import Basename, Dirname
from ..systemv import MIPS64ELSysVModel


class MIPS64ELSysVBasename(Basename, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVDirname(Dirname, MIPS64ELSysVModel):
    pass


__all__ = [
    "MIPS64ELSysVBasename",
    "MIPS64ELSysVDirname",
]
