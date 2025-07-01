from ...c99 import (
    Abs,
    Atof,
    Atoi,
    Atol,
    Atoll,
    Calloc,
    Div,
    Exit,
    Free,
    LAbs,
    LDiv,
    LLAbs,
    LLDiv,
    Malloc,
    QSort,
    Rand,
    Realloc,
    Srand,
)
from ..systemv import AArch64SysVModel


class AArch64SysVAbs(Abs, AArch64SysVModel):
    pass


class AArch64SysVLAbs(LAbs, AArch64SysVModel):
    pass


class AArch64SysVLLAbs(LLAbs, AArch64SysVModel):
    pass


class AArch64SysVAtof(Atof, AArch64SysVModel):
    pass


class AArch64SysVAtoi(Atoi, AArch64SysVModel):
    pass


class AArch64SysVAtol(Atol, AArch64SysVModel):
    pass


class AArch64SysVAtoll(Atoll, AArch64SysVModel):
    pass


class AArch64SysVCalloc(Calloc, AArch64SysVModel):
    pass


class AArch64SysVDiv(Div, AArch64SysVModel):
    pass


class AArch64SysVLDiv(LDiv, AArch64SysVModel):
    pass


class AArch64SysVLLDiv(LLDiv, AArch64SysVModel):
    pass


class AArch64SysVExit(Exit, AArch64SysVModel):
    pass


class AArch64SysVFree(Free, AArch64SysVModel):
    pass


class AArch64SysVMalloc(Malloc, AArch64SysVModel):
    pass


class AArch64SysVQSort(QSort, AArch64SysVModel):
    pass


class AArch64SysVRand(Rand, AArch64SysVModel):
    pass


class AArch64SysVRealloc(Realloc, AArch64SysVModel):
    pass


class AArch64SysVSrand(Srand, AArch64SysVModel):
    pass


__all__ = [
    "AArch64SysVAbs",
    "AArch64SysVLAbs",
    "AArch64SysVLLAbs",
    "AArch64SysVAtof",
    "AArch64SysVAtoi",
    "AArch64SysVAtol",
    "AArch64SysVAtoll",
    "AArch64SysVCalloc",
    "AArch64SysVDiv",
    "AArch64SysVLDiv",
    "AArch64SysVLLDiv",
    "AArch64SysVExit",
    "AArch64SysVFree",
    "AArch64SysVMalloc",
    "AArch64SysVQSort",
    "AArch64SysVRand",
    "AArch64SysVRealloc",
    "AArch64SysVSrand",
]
