from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import MicroMIPSSysVModel


class MicroMIPSSysVCtypeBLoc(CtypeBLoc, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVCtypeTolowerLoc(CtypeTolowerLoc, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVCtypeToupperLoc(CtypeToupperLoc, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVTolower(Tolower, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVToupper(Toupper, MicroMIPSSysVModel):
    pass


__all__ = [
    "MicroMIPSSysVCtypeBLoc",
    "MicroMIPSSysVCtypeTolowerLoc",
    "MicroMIPSSysVCtypeToupperLoc",
    "MicroMIPSSysVTolower",
    "MicroMIPSSysVToupper",
]
