from ....posix.libgen import Basename, Dirname
from ..systemv import ArmV8RBESysVModel


class ArmV8RBESysVBasename(Basename, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVDirname(Dirname, ArmV8RBESysVModel):
    pass


__all__ = [
    "ArmV8RBESysVBasename",
    "ArmV8RBESysVDirname",
]
