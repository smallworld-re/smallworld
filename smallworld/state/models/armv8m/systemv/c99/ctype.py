from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import ArmV8MSysVModel


class ArmV8MSysVCtypeBLoc(CtypeBLoc, ArmV8MSysVModel):
    pass


class ArmV8MSysVCtypeTolowerLoc(CtypeTolowerLoc, ArmV8MSysVModel):
    pass


class ArmV8MSysVCtypeToupperLoc(CtypeToupperLoc, ArmV8MSysVModel):
    pass


class ArmV8MSysVTolower(Tolower, ArmV8MSysVModel):
    pass


class ArmV8MSysVToupper(Toupper, ArmV8MSysVModel):
    pass


__all__ = [
    "ArmV8MSysVCtypeBLoc",
    "ArmV8MSysVCtypeTolowerLoc",
    "ArmV8MSysVCtypeToupperLoc",
    "ArmV8MSysVTolower",
    "ArmV8MSysVToupper",
]
