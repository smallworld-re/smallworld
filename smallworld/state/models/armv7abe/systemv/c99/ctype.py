from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import ArmV7ABESysVModel


class ArmV7ABESysVCtypeBLoc(CtypeBLoc, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVCtypeTolowerLoc(CtypeTolowerLoc, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVCtypeToupperLoc(CtypeToupperLoc, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVTolower(Tolower, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVToupper(Toupper, ArmV7ABESysVModel):
    pass


__all__ = [
    "ArmV7ABESysVCtypeBLoc",
    "ArmV7ABESysVCtypeTolowerLoc",
    "ArmV7ABESysVCtypeToupperLoc",
    "ArmV7ABESysVTolower",
    "ArmV7ABESysVToupper",
]
