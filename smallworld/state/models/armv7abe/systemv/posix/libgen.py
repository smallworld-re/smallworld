from ....posix.libgen import Basename, Dirname
from ..systemv import ArmV7ABESysVModel


class ArmV7ABESysVBasename(Basename, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVDirname(Dirname, ArmV7ABESysVModel):
    pass


__all__ = [
    "ArmV7ABESysVBasename",
    "ArmV7ABESysVDirname",
]
