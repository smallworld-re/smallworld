from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import ArmV8ASysVModel


class ArmV8ASysVCtypeBLoc(CtypeBLoc, ArmV8ASysVModel):
    pass


class ArmV8ASysVCtypeTolowerLoc(CtypeTolowerLoc, ArmV8ASysVModel):
    pass


class ArmV8ASysVCtypeToupperLoc(CtypeToupperLoc, ArmV8ASysVModel):
    pass


class ArmV8ASysVTolower(Tolower, ArmV8ASysVModel):
    pass


class ArmV8ASysVToupper(Toupper, ArmV8ASysVModel):
    pass


__all__ = [
    "ArmV8ASysVCtypeBLoc",
    "ArmV8ASysVCtypeTolowerLoc",
    "ArmV8ASysVCtypeToupperLoc",
    "ArmV8ASysVTolower",
    "ArmV8ASysVToupper",
]
