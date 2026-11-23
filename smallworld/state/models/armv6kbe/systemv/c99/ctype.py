from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import ArmV6KBESysVModel


class ArmV6KBESysVCtypeBLoc(CtypeBLoc, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVCtypeTolowerLoc(CtypeTolowerLoc, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVCtypeToupperLoc(CtypeToupperLoc, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVTolower(Tolower, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVToupper(Toupper, ArmV6KBESysVModel):
    pass


__all__ = [
    "ArmV6KBESysVCtypeBLoc",
    "ArmV6KBESysVCtypeTolowerLoc",
    "ArmV6KBESysVCtypeToupperLoc",
    "ArmV6KBESysVTolower",
    "ArmV6KBESysVToupper",
]
