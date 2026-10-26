from ....posix.libgen import Basename, Dirname
from ..systemv import ArmV7EMSysVModel


class ArmV7EMSysVBasename(Basename, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVDirname(Dirname, ArmV7EMSysVModel):
    pass


__all__ = [
    "ArmV7EMSysVBasename",
    "ArmV7EMSysVDirname",
]
