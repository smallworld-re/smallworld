from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import ArmV4TBESysVModel


class ArmV4TBESysVCtypeBLoc(CtypeBLoc, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVCtypeTolowerLoc(CtypeTolowerLoc, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVCtypeToupperLoc(CtypeToupperLoc, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVTolower(Tolower, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVToupper(Toupper, ArmV4TBESysVModel):
    pass


__all__ = [
    "ArmV4TBESysVCtypeBLoc",
    "ArmV4TBESysVCtypeTolowerLoc",
    "ArmV4TBESysVCtypeToupperLoc",
    "ArmV4TBESysVTolower",
    "ArmV4TBESysVToupper",
]
