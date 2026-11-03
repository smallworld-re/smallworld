from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import AArch64V85ABESysVModel


class AArch64V85ABESysVCtypeBLoc(CtypeBLoc, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVCtypeTolowerLoc(CtypeTolowerLoc, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVCtypeToupperLoc(CtypeToupperLoc, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVTolower(Tolower, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVToupper(Toupper, AArch64V85ABESysVModel):
    pass


__all__ = [
    "AArch64V85ABESysVCtypeBLoc",
    "AArch64V85ABESysVCtypeTolowerLoc",
    "AArch64V85ABESysVCtypeToupperLoc",
    "AArch64V85ABESysVTolower",
    "AArch64V85ABESysVToupper",
]
