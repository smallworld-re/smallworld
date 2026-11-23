from ....posix.libgen import Basename, Dirname
from ..systemv import ArmV7MSysVModel


class ArmV7MSysVBasename(Basename, ArmV7MSysVModel):
    pass


class ArmV7MSysVDirname(Dirname, ArmV7MSysVModel):
    pass


__all__ = [
    "ArmV7MSysVBasename",
    "ArmV7MSysVDirname",
]
