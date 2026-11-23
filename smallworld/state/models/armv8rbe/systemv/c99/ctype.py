from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import ArmV8RBESysVModel


class ArmV8RBESysVCtypeBLoc(CtypeBLoc, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVCtypeTolowerLoc(CtypeTolowerLoc, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVCtypeToupperLoc(CtypeToupperLoc, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVTolower(Tolower, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVToupper(Toupper, ArmV8RBESysVModel):
    pass


__all__ = [
    "ArmV8RBESysVCtypeBLoc",
    "ArmV8RBESysVCtypeTolowerLoc",
    "ArmV8RBESysVCtypeToupperLoc",
    "ArmV8RBESysVTolower",
    "ArmV8RBESysVToupper",
]
