from ....c99.ctype import CtypeBLoc, CtypeTolowerLoc, CtypeToupperLoc, Tolower, Toupper
from ..systemv import LoongArch64SysVModel


class LoongArch64SysVCtypeBLoc(CtypeBLoc, LoongArch64SysVModel):
    pass


class LoongArch64SysVCtypeTolowerLoc(CtypeTolowerLoc, LoongArch64SysVModel):
    pass


class LoongArch64SysVCtypeToupperLoc(CtypeToupperLoc, LoongArch64SysVModel):
    pass


class LoongArch64SysVTolower(Tolower, LoongArch64SysVModel):
    pass


class LoongArch64SysVToupper(Toupper, LoongArch64SysVModel):
    pass


__all__ = [
    "LoongArch64SysVCtypeBLoc",
    "LoongArch64SysVCtypeTolowerLoc",
    "LoongArch64SysVCtypeToupperLoc",
    "LoongArch64SysVTolower",
    "LoongArch64SysVToupper",
]
