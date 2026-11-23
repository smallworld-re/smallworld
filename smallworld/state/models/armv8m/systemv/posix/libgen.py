from ....posix.libgen import Basename, Dirname
from ..systemv import ArmV8MSysVModel


class ArmV8MSysVBasename(Basename, ArmV8MSysVModel):
    pass


class ArmV8MSysVDirname(Dirname, ArmV8MSysVModel):
    pass


__all__ = [
    "ArmV8MSysVBasename",
    "ArmV8MSysVDirname",
]
