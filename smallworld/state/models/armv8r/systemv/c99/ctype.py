from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import ArmV8RSysVModel


class ArmV8RSysVCtypeBLoc(CtypeBLoc, ArmV8RSysVModel):
    pass


class ArmV8RSysVCtypeTolowerLoc(CtypeTolowerLoc, ArmV8RSysVModel):
    pass


class ArmV8RSysVCtypeToupperLoc(CtypeToupperLoc, ArmV8RSysVModel):
    pass


class ArmV8RSysVTolower(Tolower, ArmV8RSysVModel):
    pass


class ArmV8RSysVToupper(Toupper, ArmV8RSysVModel):
    pass


__all__ = [
    "ArmV8RSysVCtypeBLoc",
    "ArmV8RSysVCtypeTolowerLoc",
    "ArmV8RSysVCtypeToupperLoc",
    "ArmV8RSysVTolower",
    "ArmV8RSysVToupper",
]
