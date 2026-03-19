from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import ArmHFSysVModel


class ArmHFSysVCtypeBLoc(CtypeBLoc, ArmHFSysVModel):
    pass


class ArmHFSysVCtypeTolowerLoc(CtypeTolowerLoc, ArmHFSysVModel):
    pass


class ArmHFSysVCtypeToupperLoc(CtypeToupperLoc, ArmHFSysVModel):
    pass


class ArmHFSysVTolower(Tolower, ArmHFSysVModel):
    pass


class ArmHFSysVToupper(Toupper, ArmHFSysVModel):
    pass


__all__ = [
    "ArmHFSysVCtypeBLoc",
    "ArmHFSysVCtypeTolowerLoc",
    "ArmHFSysVCtypeToupperLoc",
    "ArmHFSysVTolower",
    "ArmHFSysVToupper",
]
