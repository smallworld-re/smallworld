from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import MIPS64SysVModel


class MIPS64SysVCtypeBLoc(CtypeBLoc, MIPS64SysVModel):
    pass


class MIPS64SysVCtypeTolowerLoc(CtypeTolowerLoc, MIPS64SysVModel):
    pass


class MIPS64SysVCtypeToupperLoc(CtypeToupperLoc, MIPS64SysVModel):
    pass


class MIPS64SysVTolower(Tolower, MIPS64SysVModel):
    pass


class MIPS64SysVToupper(Toupper, MIPS64SysVModel):
    pass


__all__ = [
    "MIPS64SysVCtypeBLoc",
    "MIPS64SysVCtypeTolowerLoc",
    "MIPS64SysVCtypeToupperLoc",
    "MIPS64SysVTolower",
    "MIPS64SysVToupper",
]
