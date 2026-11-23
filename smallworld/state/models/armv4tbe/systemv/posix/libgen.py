from ....posix.libgen import Basename, Dirname
from ..systemv import ArmV4TBESysVModel


class ArmV4TBESysVBasename(Basename, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVDirname(Dirname, ArmV4TBESysVModel):
    pass


__all__ = [
    "ArmV4TBESysVBasename",
    "ArmV4TBESysVDirname",
]
