from ....posix.libgen import Basename, Dirname
from ..systemv import ArmV8RSysVModel


class ArmV8RSysVBasename(Basename, ArmV8RSysVModel):
    pass


class ArmV8RSysVDirname(Dirname, ArmV8RSysVModel):
    pass


__all__ = [
    "ArmV8RSysVBasename",
    "ArmV8RSysVDirname",
]
