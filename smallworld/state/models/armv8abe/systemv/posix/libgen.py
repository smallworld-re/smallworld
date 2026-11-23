from ....posix.libgen import Basename, Dirname
from ..systemv import ArmV8ABESysVModel


class ArmV8ABESysVBasename(Basename, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVDirname(Dirname, ArmV8ABESysVModel):
    pass


__all__ = [
    "ArmV8ABESysVBasename",
    "ArmV8ABESysVDirname",
]
