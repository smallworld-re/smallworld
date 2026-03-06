from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import AMD64SysVModel


class AMD64SysVCtypeBLoc(CtypeBLoc, AMD64SysVModel):
    pass


class AMD64SysVCtypeTolowerLoc(CtypeTolowerLoc, AMD64SysVModel):
    pass


class AMD64SysVCtypeToupperLoc(CtypeToupperLoc, AMD64SysVModel):
    pass


class AMD64SysVTolower(Tolower, AMD64SysVModel):
    pass


class AMD64SysVToupper(Toupper, AMD64SysVModel):
    pass


__all__ = [
    "AMD64SysVCtypeBLoc",
    "AMD64SysVCtypeTolowerLoc",
    "AMD64SysVCtypeToupperLoc",
    "AMD64SysVTolower",
    "AMD64SysVToupper",
]
