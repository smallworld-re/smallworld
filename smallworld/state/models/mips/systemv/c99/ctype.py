from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import MIPSSysVModel


class MIPSSysVCtypeBLoc(CtypeBLoc, MIPSSysVModel):
    pass


class MIPSSysVCtypeTolowerLoc(CtypeTolowerLoc, MIPSSysVModel):
    pass


class MIPSSysVCtypeToupperLoc(CtypeToupperLoc, MIPSSysVModel):
    pass


class MIPSSysVTolower(Tolower, MIPSSysVModel):
    pass


class MIPSSysVToupper(Toupper, MIPSSysVModel):
    pass


__all__ = [
    "MIPSSysVCtypeBLoc",
    "MIPSSysVCtypeTolowerLoc",
    "MIPSSysVCtypeToupperLoc",
    "MIPSSysVTolower",
    "MIPSSysVToupper",
]
