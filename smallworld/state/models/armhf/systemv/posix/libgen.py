from ....posix.libgen import Basename, Dirname
from ..systemv import ArmHFSysVModel


class ArmHFSysVBasename(Basename, ArmHFSysVModel):
    pass


class ArmHFSysVDirname(Dirname, ArmHFSysVModel):
    pass


__all__ = [
    "ArmHFSysVBasename",
    "ArmHFSysVDirname",
]
