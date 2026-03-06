from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import I386SysVModel


class I386SysVCtypeBLoc(CtypeBLoc, I386SysVModel):
    pass


class I386SysVCtypeTolowerLoc(CtypeTolowerLoc, I386SysVModel):
    pass


class I386SysVCtypeToupperLoc(CtypeToupperLoc, I386SysVModel):
    pass


class I386SysVTolower(Tolower, I386SysVModel):
    pass


class I386SysVToupper(Toupper, I386SysVModel):
    pass


__all__ = [
    "I386SysVCtypeBLoc",
    "I386SysVCtypeTolowerLoc",
    "I386SysVCtypeToupperLoc",
    "I386SysVTolower",
    "I386SysVToupper",
]
