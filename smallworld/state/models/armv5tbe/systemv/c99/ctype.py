from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import ArmV5TBESysVModel


class ArmV5TBESysVCtypeBLoc(CtypeBLoc, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVCtypeTolowerLoc(CtypeTolowerLoc, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVCtypeToupperLoc(CtypeToupperLoc, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVTolower(Tolower, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVToupper(Toupper, ArmV5TBESysVModel):
    pass


__all__ = [
    "ArmV5TBESysVCtypeBLoc",
    "ArmV5TBESysVCtypeTolowerLoc",
    "ArmV5TBESysVCtypeToupperLoc",
    "ArmV5TBESysVTolower",
    "ArmV5TBESysVToupper",
]
