from ....posix.libgen import Basename, Dirname
from ..systemv import ArmV7RBESysVModel


class ArmV7RBESysVBasename(Basename, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVDirname(Dirname, ArmV7RBESysVModel):
    pass


__all__ = [
    "ArmV7RBESysVBasename",
    "ArmV7RBESysVDirname",
]
