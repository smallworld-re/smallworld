from ....c99 import (
    Abort,
    Abs,
    Atexit,
    Atof,
    Atoi,
    Atol,
    Atoll,
    Bsearch,
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


class AMD64SysVBsearch(Bsearch, AMD64SysVModel):
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


class AMD64SysVAbort(Abort, AMD64SysVModel):
    pass


class AMD64SysVAtexit(Atexit, AMD64SysVModel):
    pass


class AMD64SysVGetenv(Getenv, AMD64SysVModel):
    pass


class AMD64SysVMblen(Mblen, AMD64SysVModel):
    pass


class AMD64SysVMbstowcs(Mbstowcs, AMD64SysVModel):
    pass


class AMD64SysVMbtowc(Mbtowc, AMD64SysVModel):
    pass


class AMD64SysVSystem(System, AMD64SysVModel):
    pass


class AMD64SysVWcstombs(Wcstombs, AMD64SysVModel):
    pass


class AMD64SysVWctomb(Wctomb, AMD64SysVModel):
    pass


__all__ = [
    "AMD64SysVAbs",
    "AMD64SysVLAbs",
    "AMD64SysVLLAbs",
    "AMD64SysVAtof",
    "AMD64SysVAtoi",
    "AMD64SysVAtol",
    "AMD64SysVAtoll",
    "AMD64SysVBsearch",
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
    "AMD64SysVAbort",
    "AMD64SysVAtexit",
    "AMD64SysVGetenv",
    "AMD64SysVMblen",
    "AMD64SysVMbstowcs",
    "AMD64SysVMbtowc",
    "AMD64SysVSystem",
    "AMD64SysVWcstombs",
    "AMD64SysVWctomb",
]
