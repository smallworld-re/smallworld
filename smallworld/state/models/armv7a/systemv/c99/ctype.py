from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import ArmV7ASysVModel


class ArmV7ASysVCtypeBLoc(CtypeBLoc, ArmV7ASysVModel):
    pass


class ArmV7ASysVCtypeTolowerLoc(CtypeTolowerLoc, ArmV7ASysVModel):
    pass


class ArmV7ASysVCtypeToupperLoc(CtypeToupperLoc, ArmV7ASysVModel):
    pass


class ArmV7ASysVTolower(Tolower, ArmV7ASysVModel):
    pass


class ArmV7ASysVToupper(Toupper, ArmV7ASysVModel):
    pass


__all__ = [
    "ArmV7ASysVCtypeBLoc",
    "ArmV7ASysVCtypeTolowerLoc",
    "ArmV7ASysVCtypeToupperLoc",
    "ArmV7ASysVTolower",
    "ArmV7ASysVToupper",
]
