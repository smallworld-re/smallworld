from ....posix.libgen import Basename, Dirname
from ..systemv import ArmV7RSysVModel


class ArmV7RSysVBasename(Basename, ArmV7RSysVModel):
    pass


class ArmV7RSysVDirname(Dirname, ArmV7RSysVModel):
    pass


__all__ = [
    "ArmV7RSysVBasename",
    "ArmV7RSysVDirname",
]
