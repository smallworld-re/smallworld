from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import ArmV5TSysVModel


class ArmV5TSysVCtypeBLoc(CtypeBLoc, ArmV5TSysVModel):
    pass


class ArmV5TSysVCtypeTolowerLoc(CtypeTolowerLoc, ArmV5TSysVModel):
    pass


class ArmV5TSysVCtypeToupperLoc(CtypeToupperLoc, ArmV5TSysVModel):
    pass


class ArmV5TSysVTolower(Tolower, ArmV5TSysVModel):
    pass


class ArmV5TSysVToupper(Toupper, ArmV5TSysVModel):
    pass


__all__ = [
    "ArmV5TSysVCtypeBLoc",
    "ArmV5TSysVCtypeTolowerLoc",
    "ArmV5TSysVCtypeToupperLoc",
    "ArmV5TSysVTolower",
    "ArmV5TSysVToupper",
]
