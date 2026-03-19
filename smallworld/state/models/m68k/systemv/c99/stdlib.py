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
from ..systemv import M68KSysVModel


class M68KSysVAbs(Abs, M68KSysVModel):
    pass


class M68KSysVLAbs(LAbs, M68KSysVModel):
    pass


class M68KSysVLLAbs(LLAbs, M68KSysVModel):
    pass


class M68KSysVAtof(Atof, M68KSysVModel):
    pass


class M68KSysVAtoi(Atoi, M68KSysVModel):
    pass


class M68KSysVAtol(Atol, M68KSysVModel):
    pass


class M68KSysVAtoll(Atoll, M68KSysVModel):
    pass


class M68KSysVBsearch(Bsearch, M68KSysVModel):
    pass


class M68KSysVCalloc(Calloc, M68KSysVModel):
    pass


class M68KSysVDiv(Div, M68KSysVModel):
    pass


class M68KSysVLDiv(LDiv, M68KSysVModel):
    pass


class M68KSysVLLDiv(LLDiv, M68KSysVModel):
    pass


class M68KSysVExit(Exit, M68KSysVModel):
    pass


class M68KSysVFree(Free, M68KSysVModel):
    pass


class M68KSysVMalloc(Malloc, M68KSysVModel):
    pass


class M68KSysVQSort(QSort, M68KSysVModel):
    pass


class M68KSysVRand(Rand, M68KSysVModel):
    pass


class M68KSysVRealloc(Realloc, M68KSysVModel):
    pass


class M68KSysVSrand(Srand, M68KSysVModel):
    pass


class M68KSysVAbort(Abort, M68KSysVModel):
    pass


class M68KSysVAtexit(Atexit, M68KSysVModel):
    pass


class M68KSysVGetenv(Getenv, M68KSysVModel):
    pass


class M68KSysVMblen(Mblen, M68KSysVModel):
    pass


class M68KSysVMbstowcs(Mbstowcs, M68KSysVModel):
    pass


class M68KSysVMbtowc(Mbtowc, M68KSysVModel):
    pass


class M68KSysVSystem(System, M68KSysVModel):
    pass


class M68KSysVWcstombs(Wcstombs, M68KSysVModel):
    pass


class M68KSysVWctomb(Wctomb, M68KSysVModel):
    pass


__all__ = [
    "M68KSysVAbs",
    "M68KSysVLAbs",
    "M68KSysVLLAbs",
    "M68KSysVAtof",
    "M68KSysVAtoi",
    "M68KSysVAtol",
    "M68KSysVAtoll",
    "M68KSysVBsearch",
    "M68KSysVCalloc",
    "M68KSysVDiv",
    "M68KSysVLDiv",
    "M68KSysVLLDiv",
    "M68KSysVExit",
    "M68KSysVFree",
    "M68KSysVMalloc",
    "M68KSysVQSort",
    "M68KSysVRand",
    "M68KSysVRealloc",
    "M68KSysVSrand",
    "M68KSysVAbort",
    "M68KSysVAtexit",
    "M68KSysVGetenv",
    "M68KSysVMblen",
    "M68KSysVMbstowcs",
    "M68KSysVMbtowc",
    "M68KSysVSystem",
    "M68KSysVWcstombs",
    "M68KSysVWctomb",
]
