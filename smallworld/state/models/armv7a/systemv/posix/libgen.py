from ....posix.libgen import Basename, Dirname
from ..systemv import ArmV7ASysVModel


class ArmV7ASysVBasename(Basename, ArmV7ASysVModel):
    pass


class ArmV7ASysVDirname(Dirname, ArmV7ASysVModel):
    pass


__all__ = [
    "ArmV7ASysVBasename",
    "ArmV7ASysVDirname",
]
