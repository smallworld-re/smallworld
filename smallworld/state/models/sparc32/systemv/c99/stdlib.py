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
from ..systemv import SPARC32SysVModel


class SPARC32SysVAbs(Abs, SPARC32SysVModel):
    pass


class SPARC32SysVLAbs(LAbs, SPARC32SysVModel):
    pass


class SPARC32SysVLLAbs(LLAbs, SPARC32SysVModel):
    pass


class SPARC32SysVAtof(Atof, SPARC32SysVModel):
    pass


class SPARC32SysVAtoi(Atoi, SPARC32SysVModel):
    pass


class SPARC32SysVAtol(Atol, SPARC32SysVModel):
    pass


class SPARC32SysVAtoll(Atoll, SPARC32SysVModel):
    pass


class SPARC32SysVBsearch(Bsearch, SPARC32SysVModel):
    pass


class SPARC32SysVCalloc(Calloc, SPARC32SysVModel):
    pass


class SPARC32SysVDiv(Div, SPARC32SysVModel):
    pass


class SPARC32SysVLDiv(LDiv, SPARC32SysVModel):
    pass


class SPARC32SysVLLDiv(LLDiv, SPARC32SysVModel):
    pass


class SPARC32SysVExit(Exit, SPARC32SysVModel):
    pass


class SPARC32SysVFree(Free, SPARC32SysVModel):
    pass


class SPARC32SysVMalloc(Malloc, SPARC32SysVModel):
    pass


class SPARC32SysVQSort(QSort, SPARC32SysVModel):
    pass


class SPARC32SysVRand(Rand, SPARC32SysVModel):
    pass


class SPARC32SysVRealloc(Realloc, SPARC32SysVModel):
    pass


class SPARC32SysVSrand(Srand, SPARC32SysVModel):
    pass


class SPARC32SysVAbort(Abort, SPARC32SysVModel):
    pass


class SPARC32SysVAtexit(Atexit, SPARC32SysVModel):
    pass


class SPARC32SysVGetenv(Getenv, SPARC32SysVModel):
    pass


class SPARC32SysVMblen(Mblen, SPARC32SysVModel):
    pass


class SPARC32SysVMbstowcs(Mbstowcs, SPARC32SysVModel):
    pass


class SPARC32SysVMbtowc(Mbtowc, SPARC32SysVModel):
    pass


class SPARC32SysVSystem(System, SPARC32SysVModel):
    pass


class SPARC32SysVWcstombs(Wcstombs, SPARC32SysVModel):
    pass


class SPARC32SysVWctomb(Wctomb, SPARC32SysVModel):
    pass


__all__ = [
    "SPARC32SysVAbs",
    "SPARC32SysVLAbs",
    "SPARC32SysVLLAbs",
    "SPARC32SysVAtof",
    "SPARC32SysVAtoi",
    "SPARC32SysVAtol",
    "SPARC32SysVAtoll",
    "SPARC32SysVBsearch",
    "SPARC32SysVCalloc",
    "SPARC32SysVDiv",
    "SPARC32SysVLDiv",
    "SPARC32SysVLLDiv",
    "SPARC32SysVExit",
    "SPARC32SysVFree",
    "SPARC32SysVMalloc",
    "SPARC32SysVQSort",
    "SPARC32SysVRand",
    "SPARC32SysVRealloc",
    "SPARC32SysVSrand",
    "SPARC32SysVAbort",
    "SPARC32SysVAtexit",
    "SPARC32SysVGetenv",
    "SPARC32SysVMblen",
    "SPARC32SysVMbstowcs",
    "SPARC32SysVMbtowc",
    "SPARC32SysVSystem",
    "SPARC32SysVWcstombs",
    "SPARC32SysVWctomb",
]
