from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import AArch64BESysVModel


class AArch64BESysVCtypeBLoc(CtypeBLoc, AArch64BESysVModel):
    pass


class AArch64BESysVCtypeTolowerLoc(CtypeTolowerLoc, AArch64BESysVModel):
    pass


class AArch64BESysVCtypeToupperLoc(CtypeToupperLoc, AArch64BESysVModel):
    pass


class AArch64BESysVTolower(Tolower, AArch64BESysVModel):
    pass


class AArch64BESysVToupper(Toupper, AArch64BESysVModel):
    pass


__all__ = [
    "AArch64BESysVCtypeBLoc",
    "AArch64BESysVCtypeTolowerLoc",
    "AArch64BESysVCtypeToupperLoc",
    "AArch64BESysVTolower",
    "AArch64BESysVToupper",
]
