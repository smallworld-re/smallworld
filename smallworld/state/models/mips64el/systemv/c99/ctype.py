from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import MIPS64ELSysVModel


class MIPS64ELSysVCtypeBLoc(CtypeBLoc, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVCtypeTolowerLoc(CtypeTolowerLoc, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVCtypeToupperLoc(CtypeToupperLoc, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVTolower(Tolower, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVToupper(Toupper, MIPS64ELSysVModel):
    pass


__all__ = [
    "MIPS64ELSysVCtypeBLoc",
    "MIPS64ELSysVCtypeTolowerLoc",
    "MIPS64ELSysVCtypeToupperLoc",
    "MIPS64ELSysVTolower",
    "MIPS64ELSysVToupper",
]
