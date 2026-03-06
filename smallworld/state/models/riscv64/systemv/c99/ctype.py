from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import RiscV64SysVModel


class RiscV64SysVCtypeBLoc(CtypeBLoc, RiscV64SysVModel):
    pass


class RiscV64SysVCtypeTolowerLoc(CtypeTolowerLoc, RiscV64SysVModel):
    pass


class RiscV64SysVCtypeToupperLoc(CtypeToupperLoc, RiscV64SysVModel):
    pass


class RiscV64SysVTolower(Tolower, RiscV64SysVModel):
    pass


class RiscV64SysVToupper(Toupper, RiscV64SysVModel):
    pass


__all__ = [
    "RiscV64SysVCtypeBLoc",
    "RiscV64SysVCtypeTolowerLoc",
    "RiscV64SysVCtypeToupperLoc",
    "RiscV64SysVTolower",
    "RiscV64SysVToupper",
]
