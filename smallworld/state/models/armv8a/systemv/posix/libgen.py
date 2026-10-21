from ....posix.libgen import Basename, Dirname
from ..systemv import ArmV8ASysVModel


class ArmV8ASysVBasename(Basename, ArmV8ASysVModel):
    pass


class ArmV8ASysVDirname(Dirname, ArmV8ASysVModel):
    pass


__all__ = [
    "ArmV8ASysVBasename",
    "ArmV8ASysVDirname",
]
