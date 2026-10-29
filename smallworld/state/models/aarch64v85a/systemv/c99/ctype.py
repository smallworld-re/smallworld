from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import AArch64V85ASysVModel


class AArch64V85ASysVCtypeBLoc(CtypeBLoc, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVCtypeTolowerLoc(CtypeTolowerLoc, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVCtypeToupperLoc(CtypeToupperLoc, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVTolower(Tolower, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVToupper(Toupper, AArch64V85ASysVModel):
    pass


__all__ = [
    "AArch64V85ASysVCtypeBLoc",
    "AArch64V85ASysVCtypeTolowerLoc",
    "AArch64V85ASysVCtypeToupperLoc",
    "AArch64V85ASysVTolower",
    "AArch64V85ASysVToupper",
]
