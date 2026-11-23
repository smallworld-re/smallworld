from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import ArmV6MSysVModel


class ArmV6MSysVCtypeBLoc(CtypeBLoc, ArmV6MSysVModel):
    pass


class ArmV6MSysVCtypeTolowerLoc(CtypeTolowerLoc, ArmV6MSysVModel):
    pass


class ArmV6MSysVCtypeToupperLoc(CtypeToupperLoc, ArmV6MSysVModel):
    pass


class ArmV6MSysVTolower(Tolower, ArmV6MSysVModel):
    pass


class ArmV6MSysVToupper(Toupper, ArmV6MSysVModel):
    pass


__all__ = [
    "ArmV6MSysVCtypeBLoc",
    "ArmV6MSysVCtypeTolowerLoc",
    "ArmV6MSysVCtypeToupperLoc",
    "ArmV6MSysVTolower",
    "ArmV6MSysVToupper",
]
