from ....posix.libgen import Basename, Dirname
from ..systemv import ArmV6KBESysVModel


class ArmV6KBESysVBasename(Basename, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVDirname(Dirname, ArmV6KBESysVModel):
    pass


__all__ = [
    "ArmV6KBESysVBasename",
    "ArmV6KBESysVDirname",
]
