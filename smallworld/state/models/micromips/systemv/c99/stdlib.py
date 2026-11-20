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
from ..systemv import MicroMIPSSysVModel


class MicroMIPSSysVAbs(Abs, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVLAbs(LAbs, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVLLAbs(LLAbs, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVAtof(Atof, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVAtoi(Atoi, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVAtol(Atol, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVAtoll(Atoll, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVBsearch(Bsearch, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVCalloc(Calloc, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVDiv(Div, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVLDiv(LDiv, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVLLDiv(LLDiv, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVExit(Exit, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVFree(Free, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVMalloc(Malloc, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVQSort(QSort, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVRand(Rand, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVRealloc(Realloc, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSrand(Srand, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVAbort(Abort, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVAtexit(Atexit, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVGetenv(Getenv, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVMblen(Mblen, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVMbstowcs(Mbstowcs, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVMbtowc(Mbtowc, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSystem(System, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVWcstombs(Wcstombs, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVWctomb(Wctomb, MicroMIPSSysVModel):
    pass


__all__ = [
    "MicroMIPSSysVAbs",
    "MicroMIPSSysVLAbs",
    "MicroMIPSSysVLLAbs",
    "MicroMIPSSysVAtof",
    "MicroMIPSSysVAtoi",
    "MicroMIPSSysVAtol",
    "MicroMIPSSysVAtoll",
    "MicroMIPSSysVBsearch",
    "MicroMIPSSysVCalloc",
    "MicroMIPSSysVDiv",
    "MicroMIPSSysVLDiv",
    "MicroMIPSSysVLLDiv",
    "MicroMIPSSysVExit",
    "MicroMIPSSysVFree",
    "MicroMIPSSysVMalloc",
    "MicroMIPSSysVQSort",
    "MicroMIPSSysVRand",
    "MicroMIPSSysVRealloc",
    "MicroMIPSSysVSrand",
    "MicroMIPSSysVAbort",
    "MicroMIPSSysVAtexit",
    "MicroMIPSSysVGetenv",
    "MicroMIPSSysVMblen",
    "MicroMIPSSysVMbstowcs",
    "MicroMIPSSysVMbtowc",
    "MicroMIPSSysVSystem",
    "MicroMIPSSysVWcstombs",
    "MicroMIPSSysVWctomb",
]
