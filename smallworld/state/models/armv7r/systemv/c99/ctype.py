from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import ArmV7RSysVModel


class ArmV7RSysVCtypeBLoc(CtypeBLoc, ArmV7RSysVModel):
    pass


class ArmV7RSysVCtypeTolowerLoc(CtypeTolowerLoc, ArmV7RSysVModel):
    pass


class ArmV7RSysVCtypeToupperLoc(CtypeToupperLoc, ArmV7RSysVModel):
    pass


class ArmV7RSysVTolower(Tolower, ArmV7RSysVModel):
    pass


class ArmV7RSysVToupper(Toupper, ArmV7RSysVModel):
    pass


__all__ = [
    "ArmV7RSysVCtypeBLoc",
    "ArmV7RSysVCtypeTolowerLoc",
    "ArmV7RSysVCtypeToupperLoc",
    "ArmV7RSysVTolower",
    "ArmV7RSysVToupper",
]
