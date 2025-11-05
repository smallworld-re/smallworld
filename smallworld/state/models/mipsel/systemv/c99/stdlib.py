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
from ..systemv import MIPSELSysVModel


class MIPSELSysVAbs(Abs, MIPSELSysVModel):
    pass


class MIPSELSysVLAbs(LAbs, MIPSELSysVModel):
    pass


class MIPSELSysVLLAbs(LLAbs, MIPSELSysVModel):
    pass


class MIPSELSysVAtof(Atof, MIPSELSysVModel):
    pass


class MIPSELSysVAtoi(Atoi, MIPSELSysVModel):
    pass


class MIPSELSysVAtol(Atol, MIPSELSysVModel):
    pass


class MIPSELSysVAtoll(Atoll, MIPSELSysVModel):
    pass


class MIPSELSysVBsearch(Bsearch, MIPSELSysVModel):
    pass


class MIPSELSysVCalloc(Calloc, MIPSELSysVModel):
    pass


class MIPSELSysVDiv(Div, MIPSELSysVModel):
    pass


class MIPSELSysVLDiv(LDiv, MIPSELSysVModel):
    pass


class MIPSELSysVLLDiv(LLDiv, MIPSELSysVModel):
    pass


class MIPSELSysVExit(Exit, MIPSELSysVModel):
    pass


class MIPSELSysVFree(Free, MIPSELSysVModel):
    pass


class MIPSELSysVMalloc(Malloc, MIPSELSysVModel):
    pass


class MIPSELSysVQSort(QSort, MIPSELSysVModel):
    pass


class MIPSELSysVRand(Rand, MIPSELSysVModel):
    pass


class MIPSELSysVRealloc(Realloc, MIPSELSysVModel):
    pass


class MIPSELSysVSrand(Srand, MIPSELSysVModel):
    pass


class MIPSELSysVAbort(Abort, MIPSELSysVModel):
    pass


class MIPSELSysVAtexit(Atexit, MIPSELSysVModel):
    pass


class MIPSELSysVGetenv(Getenv, MIPSELSysVModel):
    pass


class MIPSELSysVMblen(Mblen, MIPSELSysVModel):
    pass


class MIPSELSysVMbstowcs(Mbstowcs, MIPSELSysVModel):
    pass


class MIPSELSysVMbtowc(Mbtowc, MIPSELSysVModel):
    pass


class MIPSELSysVSystem(System, MIPSELSysVModel):
    pass


class MIPSELSysVWcstombs(Wcstombs, MIPSELSysVModel):
    pass


class MIPSELSysVWctomb(Wctomb, MIPSELSysVModel):
    pass


__all__ = [
    "MIPSELSysVAbs",
    "MIPSELSysVLAbs",
    "MIPSELSysVLLAbs",
    "MIPSELSysVAtof",
    "MIPSELSysVAtoi",
    "MIPSELSysVAtol",
    "MIPSELSysVAtoll",
    "MIPSELSysVBsearch",
    "MIPSELSysVCalloc",
    "MIPSELSysVDiv",
    "MIPSELSysVLDiv",
    "MIPSELSysVLLDiv",
    "MIPSELSysVExit",
    "MIPSELSysVFree",
    "MIPSELSysVMalloc",
    "MIPSELSysVQSort",
    "MIPSELSysVRand",
    "MIPSELSysVRealloc",
    "MIPSELSysVSrand",
    "MIPSELSysVAbort",
    "MIPSELSysVAtexit",
    "MIPSELSysVGetenv",
    "MIPSELSysVMblen",
    "MIPSELSysVMbstowcs",
    "MIPSELSysVMbtowc",
    "MIPSELSysVSystem",
    "MIPSELSysVWcstombs",
    "MIPSELSysVWctomb",
]
