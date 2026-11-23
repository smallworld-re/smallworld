from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import ArmV8ABESysVModel


class ArmV8ABESysVCtypeBLoc(CtypeBLoc, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVCtypeTolowerLoc(CtypeTolowerLoc, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVCtypeToupperLoc(CtypeToupperLoc, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVTolower(Tolower, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVToupper(Toupper, ArmV8ABESysVModel):
    pass


__all__ = [
    "ArmV8ABESysVCtypeBLoc",
    "ArmV8ABESysVCtypeTolowerLoc",
    "ArmV8ABESysVCtypeToupperLoc",
    "ArmV8ABESysVTolower",
    "ArmV8ABESysVToupper",
]
