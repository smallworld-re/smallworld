from ....c99 import (
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
from ..systemv import MIPS64SysVModel


class MIPS64SysVAbs(Abs, MIPS64SysVModel):
    pass


class MIPS64SysVLAbs(LAbs, MIPS64SysVModel):
    pass


class MIPS64SysVLLAbs(LLAbs, MIPS64SysVModel):
    pass


class MIPS64SysVAtof(Atof, MIPS64SysVModel):
    pass


class MIPS64SysVAtoi(Atoi, MIPS64SysVModel):
    pass


class MIPS64SysVAtol(Atol, MIPS64SysVModel):
    pass


class MIPS64SysVAtoll(Atoll, MIPS64SysVModel):
    pass


class MIPS64SysVCalloc(Calloc, MIPS64SysVModel):
    pass


class MIPS64SysVDiv(Div, MIPS64SysVModel):
    pass


class MIPS64SysVLDiv(LDiv, MIPS64SysVModel):
    pass


class MIPS64SysVLLDiv(LLDiv, MIPS64SysVModel):
    pass


class MIPS64SysVExit(Exit, MIPS64SysVModel):
    pass


class MIPS64SysVFree(Free, MIPS64SysVModel):
    pass


class MIPS64SysVMalloc(Malloc, MIPS64SysVModel):
    pass


class MIPS64SysVQSort(QSort, MIPS64SysVModel):
    pass


class MIPS64SysVRand(Rand, MIPS64SysVModel):
    pass


class MIPS64SysVRealloc(Realloc, MIPS64SysVModel):
    pass


class MIPS64SysVSrand(Srand, MIPS64SysVModel):
    pass


__all__ = [
    "MIPS64SysVAbs",
    "MIPS64SysVLAbs",
    "MIPS64SysVLLAbs",
    "MIPS64SysVAtof",
    "MIPS64SysVAtoi",
    "MIPS64SysVAtol",
    "MIPS64SysVAtoll",
    "MIPS64SysVCalloc",
    "MIPS64SysVDiv",
    "MIPS64SysVLDiv",
    "MIPS64SysVLLDiv",
    "MIPS64SysVExit",
    "MIPS64SysVFree",
    "MIPS64SysVMalloc",
    "MIPS64SysVQSort",
    "MIPS64SysVRand",
    "MIPS64SysVRealloc",
    "MIPS64SysVSrand",
]
