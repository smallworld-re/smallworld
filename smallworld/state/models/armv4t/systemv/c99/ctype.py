from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import ArmV4TSysVModel


class ArmV4TSysVCtypeBLoc(CtypeBLoc, ArmV4TSysVModel):
    pass


class ArmV4TSysVCtypeTolowerLoc(CtypeTolowerLoc, ArmV4TSysVModel):
    pass


class ArmV4TSysVCtypeToupperLoc(CtypeToupperLoc, ArmV4TSysVModel):
    pass


class ArmV4TSysVTolower(Tolower, ArmV4TSysVModel):
    pass


class ArmV4TSysVToupper(Toupper, ArmV4TSysVModel):
    pass


__all__ = [
    "ArmV4TSysVCtypeBLoc",
    "ArmV4TSysVCtypeTolowerLoc",
    "ArmV4TSysVCtypeToupperLoc",
    "ArmV4TSysVTolower",
    "ArmV4TSysVToupper",
]
