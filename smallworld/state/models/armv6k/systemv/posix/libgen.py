from ....posix.libgen import Basename, Dirname
from ..systemv import ArmV6KSysVModel


class ArmV6KSysVBasename(Basename, ArmV6KSysVModel):
    pass


class ArmV6KSysVDirname(Dirname, ArmV6KSysVModel):
    pass


__all__ = [
    "ArmV6KSysVBasename",
    "ArmV6KSysVDirname",
]
