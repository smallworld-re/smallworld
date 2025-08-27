from ....posix.libgen import Basename, Dirname
from ..systemv import ArmELSysVModel


class ArmELSysVBasename(Basename, ArmELSysVModel):
    pass


class ArmELSysVDirname(Dirname, ArmELSysVModel):
    pass


__all__ = [
    "ArmELSysVBasename",
    "ArmELSysVDirname",
]
