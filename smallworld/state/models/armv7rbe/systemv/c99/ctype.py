from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import ArmV7RBESysVModel


class ArmV7RBESysVCtypeBLoc(CtypeBLoc, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVCtypeTolowerLoc(CtypeTolowerLoc, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVCtypeToupperLoc(CtypeToupperLoc, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVTolower(Tolower, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVToupper(Toupper, ArmV7RBESysVModel):
    pass


__all__ = [
    "ArmV7RBESysVCtypeBLoc",
    "ArmV7RBESysVCtypeTolowerLoc",
    "ArmV7RBESysVCtypeToupperLoc",
    "ArmV7RBESysVTolower",
    "ArmV7RBESysVToupper",
]
