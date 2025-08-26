from ....posix.libgen import Basename, Dirname
from ..systemv import MIPSELSysVModel


class MIPSELSysVBasename(Basename, MIPSELSysVModel):
    pass


class MIPSELSysVDirname(Dirname, MIPSELSysVModel):
    pass


__all__ = [
    "MIPSELSysVBasename",
    "MIPSELSysVDirname",
]
