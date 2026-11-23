from ....posix.libgen import Basename, Dirname
from ..systemv import ArmV4TSysVModel


class ArmV4TSysVBasename(Basename, ArmV4TSysVModel):
    pass


class ArmV4TSysVDirname(Dirname, ArmV4TSysVModel):
    pass


__all__ = [
    "ArmV4TSysVBasename",
    "ArmV4TSysVDirname",
]
