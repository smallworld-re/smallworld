from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import ArmELSysVModel


class ArmELSysVCtypeBLoc(CtypeBLoc, ArmELSysVModel):
    pass


class ArmELSysVCtypeTolowerLoc(CtypeTolowerLoc, ArmELSysVModel):
    pass


class ArmELSysVCtypeToupperLoc(CtypeToupperLoc, ArmELSysVModel):
    pass


class ArmELSysVTolower(Tolower, ArmELSysVModel):
    pass


class ArmELSysVToupper(Toupper, ArmELSysVModel):
    pass


__all__ = [
    "ArmELSysVCtypeBLoc",
    "ArmELSysVCtypeTolowerLoc",
    "ArmELSysVCtypeToupperLoc",
    "ArmELSysVTolower",
    "ArmELSysVToupper",
]
