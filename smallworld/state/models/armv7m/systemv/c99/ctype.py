from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import ArmV7MSysVModel


class ArmV7MSysVCtypeBLoc(CtypeBLoc, ArmV7MSysVModel):
    pass


class ArmV7MSysVCtypeTolowerLoc(CtypeTolowerLoc, ArmV7MSysVModel):
    pass


class ArmV7MSysVCtypeToupperLoc(CtypeToupperLoc, ArmV7MSysVModel):
    pass


class ArmV7MSysVTolower(Tolower, ArmV7MSysVModel):
    pass


class ArmV7MSysVToupper(Toupper, ArmV7MSysVModel):
    pass


__all__ = [
    "ArmV7MSysVCtypeBLoc",
    "ArmV7MSysVCtypeTolowerLoc",
    "ArmV7MSysVCtypeToupperLoc",
    "ArmV7MSysVTolower",
    "ArmV7MSysVToupper",
]
