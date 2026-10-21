from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import SPARC32SysVModel


class SPARC32SysVCtypeBLoc(CtypeBLoc, SPARC32SysVModel):
    pass


class SPARC32SysVCtypeTolowerLoc(CtypeTolowerLoc, SPARC32SysVModel):
    pass


class SPARC32SysVCtypeToupperLoc(CtypeToupperLoc, SPARC32SysVModel):
    pass


class SPARC32SysVTolower(Tolower, SPARC32SysVModel):
    pass


class SPARC32SysVToupper(Toupper, SPARC32SysVModel):
    pass


__all__ = [
    "SPARC32SysVCtypeBLoc",
    "SPARC32SysVCtypeTolowerLoc",
    "SPARC32SysVCtypeToupperLoc",
    "SPARC32SysVTolower",
    "SPARC32SysVToupper",
]
