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
from ..systemv import AArch64BESysVModel


class AArch64BESysVAbs(Abs, AArch64BESysVModel):
    pass


class AArch64BESysVLAbs(LAbs, AArch64BESysVModel):
    pass


class AArch64BESysVLLAbs(LLAbs, AArch64BESysVModel):
    pass


class AArch64BESysVAtof(Atof, AArch64BESysVModel):
    pass


class AArch64BESysVAtoi(Atoi, AArch64BESysVModel):
    pass


class AArch64BESysVAtol(Atol, AArch64BESysVModel):
    pass


class AArch64BESysVAtoll(Atoll, AArch64BESysVModel):
    pass


class AArch64BESysVBsearch(Bsearch, AArch64BESysVModel):
    pass


class AArch64BESysVCalloc(Calloc, AArch64BESysVModel):
    pass


class AArch64BESysVDiv(Div, AArch64BESysVModel):
    pass


class AArch64BESysVLDiv(LDiv, AArch64BESysVModel):
    pass


class AArch64BESysVLLDiv(LLDiv, AArch64BESysVModel):
    pass


class AArch64BESysVExit(Exit, AArch64BESysVModel):
    pass


class AArch64BESysVFree(Free, AArch64BESysVModel):
    pass


class AArch64BESysVMalloc(Malloc, AArch64BESysVModel):
    pass


class AArch64BESysVQSort(QSort, AArch64BESysVModel):
    pass


class AArch64BESysVRand(Rand, AArch64BESysVModel):
    pass


class AArch64BESysVRealloc(Realloc, AArch64BESysVModel):
    pass


class AArch64BESysVSrand(Srand, AArch64BESysVModel):
    pass


class AArch64BESysVAbort(Abort, AArch64BESysVModel):
    pass


class AArch64BESysVAtexit(Atexit, AArch64BESysVModel):
    pass


class AArch64BESysVGetenv(Getenv, AArch64BESysVModel):
    pass


class AArch64BESysVMblen(Mblen, AArch64BESysVModel):
    pass


class AArch64BESysVMbstowcs(Mbstowcs, AArch64BESysVModel):
    pass


class AArch64BESysVMbtowc(Mbtowc, AArch64BESysVModel):
    pass


class AArch64BESysVSystem(System, AArch64BESysVModel):
    pass


class AArch64BESysVWcstombs(Wcstombs, AArch64BESysVModel):
    pass


class AArch64BESysVWctomb(Wctomb, AArch64BESysVModel):
    pass


__all__ = [
    "AArch64BESysVAbs",
    "AArch64BESysVLAbs",
    "AArch64BESysVLLAbs",
    "AArch64BESysVAtof",
    "AArch64BESysVAtoi",
    "AArch64BESysVAtol",
    "AArch64BESysVAtoll",
    "AArch64BESysVBsearch",
    "AArch64BESysVCalloc",
    "AArch64BESysVDiv",
    "AArch64BESysVLDiv",
    "AArch64BESysVLLDiv",
    "AArch64BESysVExit",
    "AArch64BESysVFree",
    "AArch64BESysVMalloc",
    "AArch64BESysVQSort",
    "AArch64BESysVRand",
    "AArch64BESysVRealloc",
    "AArch64BESysVSrand",
    "AArch64BESysVAbort",
    "AArch64BESysVAtexit",
    "AArch64BESysVGetenv",
    "AArch64BESysVMblen",
    "AArch64BESysVMbstowcs",
    "AArch64BESysVMbtowc",
    "AArch64BESysVSystem",
    "AArch64BESysVWcstombs",
    "AArch64BESysVWctomb",
]
