from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import ArmV6KSysVModel


class ArmV6KSysVCtypeBLoc(CtypeBLoc, ArmV6KSysVModel):
    pass


class ArmV6KSysVCtypeTolowerLoc(CtypeTolowerLoc, ArmV6KSysVModel):
    pass


class ArmV6KSysVCtypeToupperLoc(CtypeToupperLoc, ArmV6KSysVModel):
    pass


class ArmV6KSysVTolower(Tolower, ArmV6KSysVModel):
    pass


class ArmV6KSysVToupper(Toupper, ArmV6KSysVModel):
    pass


__all__ = [
    "ArmV6KSysVCtypeBLoc",
    "ArmV6KSysVCtypeTolowerLoc",
    "ArmV6KSysVCtypeToupperLoc",
    "ArmV6KSysVTolower",
    "ArmV6KSysVToupper",
]
