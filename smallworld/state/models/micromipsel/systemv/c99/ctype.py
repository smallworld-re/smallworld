from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import MicroMIPSELSysVModel


class MicroMIPSELSysVCtypeBLoc(CtypeBLoc, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVCtypeTolowerLoc(CtypeTolowerLoc, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVCtypeToupperLoc(CtypeToupperLoc, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVTolower(Tolower, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVToupper(Toupper, MicroMIPSELSysVModel):
    pass


__all__ = [
    "MicroMIPSELSysVCtypeBLoc",
    "MicroMIPSELSysVCtypeTolowerLoc",
    "MicroMIPSELSysVCtypeToupperLoc",
    "MicroMIPSELSysVTolower",
    "MicroMIPSELSysVToupper",
]
