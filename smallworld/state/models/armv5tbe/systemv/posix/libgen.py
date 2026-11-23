from ....posix.libgen import Basename, Dirname
from ..systemv import ArmV5TBESysVModel


class ArmV5TBESysVBasename(Basename, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVDirname(Dirname, ArmV5TBESysVModel):
    pass


__all__ = [
    "ArmV5TBESysVBasename",
    "ArmV5TBESysVDirname",
]
