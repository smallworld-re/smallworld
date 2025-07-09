from ....c99 import (
    Abort,
    Abs,
    Atexit,
    Atof,
    Atoi,
    Atol,
    Atoll,
    Calloc,
    Div,
    Exit,
    Free,
    Getenv,
    LAbs,
    LDiv,
    LLAbs,
    LLDiv,
    Malloc,
    Mblen,
    Mbstowcs,
    Mbtowc,
    QSort,
    Rand,
    Realloc,
    Srand,
    System,
    Wcstombs,
    Wctomb,
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


class I386SysVAbort(Abort, I386SysVModel):
    pass


class I386SysVAtexit(Atexit, I386SysVModel):
    pass


class I386SysVGetenv(Getenv, I386SysVModel):
    pass


class I386SysVMblen(Mblen, I386SysVModel):
    pass


class I386SysVMbstowcs(Mbstowcs, I386SysVModel):
    pass


class I386SysVMbtowc(Mbtowc, I386SysVModel):
    pass


class I386SysVSystem(System, I386SysVModel):
    pass


class I386SysVWcstombs(Wcstombs, I386SysVModel):
    pass


class I386SysVWctomb(Wctomb, I386SysVModel):
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
    "I386SysVAbort",
    "I386SysVAtexit",
    "I386SysVGetenv",
    "I386SysVMblen",
    "I386SysVMbstowcs",
    "I386SysVMbtowc",
    "I386SysVSystem",
    "I386SysVWcstombs",
    "I386SysVWctomb",
]
