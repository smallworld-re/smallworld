from ....posix.libgen import Basename, Dirname
from ..systemv import MicroMIPSELSysVModel


class MicroMIPSELSysVBasename(Basename, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVDirname(Dirname, MicroMIPSELSysVModel):
    pass


__all__ = [
    "MicroMIPSELSysVBasename",
    "MicroMIPSELSysVDirname",
]
