from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import MIPSELSysVModel


class MIPSELSysVCtypeBLoc(CtypeBLoc, MIPSELSysVModel):
    pass


class MIPSELSysVCtypeTolowerLoc(CtypeTolowerLoc, MIPSELSysVModel):
    pass


class MIPSELSysVCtypeToupperLoc(CtypeToupperLoc, MIPSELSysVModel):
    pass


class MIPSELSysVTolower(Tolower, MIPSELSysVModel):
    pass


class MIPSELSysVToupper(Toupper, MIPSELSysVModel):
    pass


__all__ = [
    "MIPSELSysVCtypeBLoc",
    "MIPSELSysVCtypeTolowerLoc",
    "MIPSELSysVCtypeToupperLoc",
    "MIPSELSysVTolower",
    "MIPSELSysVToupper",
]
