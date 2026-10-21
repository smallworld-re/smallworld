from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import PowerPC64SysVModel


class PowerPC64SysVCtypeBLoc(CtypeBLoc, PowerPC64SysVModel):
    pass


class PowerPC64SysVCtypeTolowerLoc(CtypeTolowerLoc, PowerPC64SysVModel):
    pass


class PowerPC64SysVCtypeToupperLoc(CtypeToupperLoc, PowerPC64SysVModel):
    pass


class PowerPC64SysVTolower(Tolower, PowerPC64SysVModel):
    pass


class PowerPC64SysVToupper(Toupper, PowerPC64SysVModel):
    pass


__all__ = [
    "PowerPC64SysVCtypeBLoc",
    "PowerPC64SysVCtypeTolowerLoc",
    "PowerPC64SysVCtypeToupperLoc",
    "PowerPC64SysVTolower",
    "PowerPC64SysVToupper",
]
