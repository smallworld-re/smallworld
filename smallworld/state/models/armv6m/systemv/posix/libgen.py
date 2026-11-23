from ....posix.libgen import Basename, Dirname
from ..systemv import ArmV6MSysVModel


class ArmV6MSysVBasename(Basename, ArmV6MSysVModel):
    pass


class ArmV6MSysVDirname(Dirname, ArmV6MSysVModel):
    pass


__all__ = [
    "ArmV6MSysVBasename",
    "ArmV6MSysVDirname",
]
