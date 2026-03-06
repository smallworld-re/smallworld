from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import PowerPCSysVModel


class PowerPCSysVCtypeBLoc(CtypeBLoc, PowerPCSysVModel):
    pass


class PowerPCSysVCtypeTolowerLoc(CtypeTolowerLoc, PowerPCSysVModel):
    pass


class PowerPCSysVCtypeToupperLoc(CtypeToupperLoc, PowerPCSysVModel):
    pass


class PowerPCSysVTolower(Tolower, PowerPCSysVModel):
    pass


class PowerPCSysVToupper(Toupper, PowerPCSysVModel):
    pass


__all__ = [
    "PowerPCSysVCtypeBLoc",
    "PowerPCSysVCtypeTolowerLoc",
    "PowerPCSysVCtypeToupperLoc",
    "PowerPCSysVTolower",
    "PowerPCSysVToupper",
]
