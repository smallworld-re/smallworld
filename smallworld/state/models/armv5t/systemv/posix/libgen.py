from ....posix.libgen import Basename, Dirname
from ..systemv import ArmV5TSysVModel


class ArmV5TSysVBasename(Basename, ArmV5TSysVModel):
    pass


class ArmV5TSysVDirname(Dirname, ArmV5TSysVModel):
    pass


__all__ = [
    "ArmV5TSysVBasename",
    "ArmV5TSysVDirname",
]
