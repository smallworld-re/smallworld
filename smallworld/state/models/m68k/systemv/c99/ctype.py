from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import M68KSysVModel


class M68KSysVCtypeBLoc(CtypeBLoc, M68KSysVModel):
    pass


class M68KSysVCtypeTolowerLoc(CtypeTolowerLoc, M68KSysVModel):
    pass


class M68KSysVCtypeToupperLoc(CtypeToupperLoc, M68KSysVModel):
    pass


class M68KSysVTolower(Tolower, M68KSysVModel):
    pass


class M68KSysVToupper(Toupper, M68KSysVModel):
    pass


__all__ = [
    "M68KSysVCtypeBLoc",
    "M68KSysVCtypeTolowerLoc",
    "M68KSysVCtypeToupperLoc",
    "M68KSysVTolower",
    "M68KSysVToupper",
]
