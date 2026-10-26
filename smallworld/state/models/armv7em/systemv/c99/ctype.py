from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import ArmV7EMSysVModel


class ArmV7EMSysVCtypeBLoc(CtypeBLoc, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVCtypeTolowerLoc(CtypeTolowerLoc, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVCtypeToupperLoc(CtypeToupperLoc, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVTolower(Tolower, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVToupper(Toupper, ArmV7EMSysVModel):
    pass


__all__ = [
    "ArmV7EMSysVCtypeBLoc",
    "ArmV7EMSysVCtypeTolowerLoc",
    "ArmV7EMSysVCtypeToupperLoc",
    "ArmV7EMSysVTolower",
    "ArmV7EMSysVToupper",
]
