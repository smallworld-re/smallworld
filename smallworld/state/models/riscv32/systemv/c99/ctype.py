from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import RiscV32SysVModel


class RiscV32SysVCtypeBLoc(CtypeBLoc, RiscV32SysVModel):
    pass


class RiscV32SysVCtypeTolowerLoc(CtypeTolowerLoc, RiscV32SysVModel):
    pass


class RiscV32SysVCtypeToupperLoc(CtypeToupperLoc, RiscV32SysVModel):
    pass


class RiscV32SysVTolower(Tolower, RiscV32SysVModel):
    pass


class RiscV32SysVToupper(Toupper, RiscV32SysVModel):
    pass


__all__ = [
    "RiscV32SysVCtypeBLoc",
    "RiscV32SysVCtypeTolowerLoc",
    "RiscV32SysVCtypeToupperLoc",
    "RiscV32SysVTolower",
    "RiscV32SysVToupper",
]
