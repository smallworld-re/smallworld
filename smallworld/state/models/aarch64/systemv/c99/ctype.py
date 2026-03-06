from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import AArch64SysVModel


class AArch64SysVCtypeBLoc(CtypeBLoc, AArch64SysVModel):
    pass


class AArch64SysVCtypeTolowerLoc(CtypeTolowerLoc, AArch64SysVModel):
    pass


class AArch64SysVCtypeToupperLoc(CtypeToupperLoc, AArch64SysVModel):
    pass


class AArch64SysVTolower(Tolower, AArch64SysVModel):
    pass


class AArch64SysVToupper(Toupper, AArch64SysVModel):
    pass


__all__ = [
    "AArch64SysVCtypeBLoc",
    "AArch64SysVCtypeTolowerLoc",
    "AArch64SysVCtypeToupperLoc",
    "AArch64SysVTolower",
    "AArch64SysVToupper",
]
