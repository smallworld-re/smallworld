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
from ..systemv import MicroMIPSELSysVModel


class MicroMIPSELSysVAbs(Abs, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVLAbs(LAbs, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVLLAbs(LLAbs, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVAtof(Atof, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVAtoi(Atoi, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVAtol(Atol, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVAtoll(Atoll, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVBsearch(Bsearch, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVCalloc(Calloc, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVDiv(Div, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVLDiv(LDiv, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVLLDiv(LLDiv, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVExit(Exit, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVFree(Free, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVMalloc(Malloc, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVQSort(QSort, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVRand(Rand, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVRealloc(Realloc, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSrand(Srand, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVAbort(Abort, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVAtexit(Atexit, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVGetenv(Getenv, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVMblen(Mblen, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVMbstowcs(Mbstowcs, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVMbtowc(Mbtowc, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSystem(System, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVWcstombs(Wcstombs, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVWctomb(Wctomb, MicroMIPSELSysVModel):
    pass


__all__ = [
    "MicroMIPSELSysVAbs",
    "MicroMIPSELSysVLAbs",
    "MicroMIPSELSysVLLAbs",
    "MicroMIPSELSysVAtof",
    "MicroMIPSELSysVAtoi",
    "MicroMIPSELSysVAtol",
    "MicroMIPSELSysVAtoll",
    "MicroMIPSELSysVBsearch",
    "MicroMIPSELSysVCalloc",
    "MicroMIPSELSysVDiv",
    "MicroMIPSELSysVLDiv",
    "MicroMIPSELSysVLLDiv",
    "MicroMIPSELSysVExit",
    "MicroMIPSELSysVFree",
    "MicroMIPSELSysVMalloc",
    "MicroMIPSELSysVQSort",
    "MicroMIPSELSysVRand",
    "MicroMIPSELSysVRealloc",
    "MicroMIPSELSysVSrand",
    "MicroMIPSELSysVAbort",
    "MicroMIPSELSysVAtexit",
    "MicroMIPSELSysVGetenv",
    "MicroMIPSELSysVMblen",
    "MicroMIPSELSysVMbstowcs",
    "MicroMIPSELSysVMbtowc",
    "MicroMIPSELSysVSystem",
    "MicroMIPSELSysVWcstombs",
    "MicroMIPSELSysVWctomb",
]
