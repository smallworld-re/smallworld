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
from ..systemv import I386SysVModel


class I386SysVAbs(Abs, I386SysVModel):
    pass


class I386SysVLAbs(LAbs, I386SysVModel):
    pass


class I386SysVLLAbs(LLAbs, I386SysVModel):
    pass


class I386SysVAtof(Atof, I386SysVModel):
    pass


class I386SysVAtoi(Atoi, I386SysVModel):
    pass


class I386SysVAtol(Atol, I386SysVModel):
    pass


class I386SysVAtoll(Atoll, I386SysVModel):
    pass


class I386SysVCalloc(Calloc, I386SysVModel):
    pass


class I386SysVDiv(Div, I386SysVModel):
    pass


class I386SysVLDiv(LDiv, I386SysVModel):
    pass


class I386SysVLLDiv(LLDiv, I386SysVModel):
    pass


class I386SysVExit(Exit, I386SysVModel):
    pass


class I386SysVFree(Free, I386SysVModel):
    pass


class I386SysVMalloc(Malloc, I386SysVModel):
    pass


class I386SysVQSort(QSort, I386SysVModel):
    pass


class I386SysVRand(Rand, I386SysVModel):
    pass


class I386SysVRealloc(Realloc, I386SysVModel):
    pass


class I386SysVSrand(Srand, I386SysVModel):
    pass


__all__ = [
    "I386SysVAbs",
    "I386SysVLAbs",
    "I386SysVLLAbs",
    "I386SysVAtof",
    "I386SysVAtoi",
    "I386SysVAtol",
    "I386SysVAtoll",
    "I386SysVCalloc",
    "I386SysVDiv",
    "I386SysVLDiv",
    "I386SysVLLDiv",
    "I386SysVExit",
    "I386SysVFree",
    "I386SysVMalloc",
    "I386SysVQSort",
    "I386SysVRand",
    "I386SysVRealloc",
    "I386SysVSrand",
]
