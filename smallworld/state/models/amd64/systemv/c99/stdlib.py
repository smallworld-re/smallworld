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
from ..systemv import AMD64SysVModel


class AMD64SysVAbs(Abs, AMD64SysVModel):
    pass


class AMD64SysVLAbs(LAbs, AMD64SysVModel):
    pass


class AMD64SysVLLAbs(LLAbs, AMD64SysVModel):
    pass


class AMD64SysVAtof(Atof, AMD64SysVModel):
    pass


class AMD64SysVAtoi(Atoi, AMD64SysVModel):
    pass


class AMD64SysVAtol(Atol, AMD64SysVModel):
    pass


class AMD64SysVAtoll(Atoll, AMD64SysVModel):
    pass


class AMD64SysVCalloc(Calloc, AMD64SysVModel):
    pass


class AMD64SysVDiv(Div, AMD64SysVModel):
    pass


class AMD64SysVLDiv(LDiv, AMD64SysVModel):
    pass


class AMD64SysVLLDiv(LLDiv, AMD64SysVModel):
    pass


class AMD64SysVExit(Exit, AMD64SysVModel):
    pass


class AMD64SysVFree(Free, AMD64SysVModel):
    pass


class AMD64SysVMalloc(Malloc, AMD64SysVModel):
    pass


class AMD64SysVQSort(QSort, AMD64SysVModel):
    pass


class AMD64SysVRand(Rand, AMD64SysVModel):
    pass


class AMD64SysVRealloc(Realloc, AMD64SysVModel):
    pass


class AMD64SysVSrand(Srand, AMD64SysVModel):
    pass


__all__ = [
    "AMD64SysVAbs",
    "AMD64SysVLAbs",
    "AMD64SysVLLAbs",
    "AMD64SysVAtof",
    "AMD64SysVAtoi",
    "AMD64SysVAtol",
    "AMD64SysVAtoll",
    "AMD64SysVCalloc",
    "AMD64SysVDiv",
    "AMD64SysVLDiv",
    "AMD64SysVLLDiv",
    "AMD64SysVExit",
    "AMD64SysVFree",
    "AMD64SysVMalloc",
    "AMD64SysVQSort",
    "AMD64SysVRand",
    "AMD64SysVRealloc",
    "AMD64SysVSrand",
]
