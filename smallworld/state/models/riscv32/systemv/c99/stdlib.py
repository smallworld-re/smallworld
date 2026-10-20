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
from ..systemv import RiscV32SysVModel


class RiscV32SysVAbs(Abs, RiscV32SysVModel):
    pass


class RiscV32SysVLAbs(LAbs, RiscV32SysVModel):
    pass


class RiscV32SysVLLAbs(LLAbs, RiscV32SysVModel):
    pass


class RiscV32SysVAtof(Atof, RiscV32SysVModel):
    pass


class RiscV32SysVAtoi(Atoi, RiscV32SysVModel):
    pass


class RiscV32SysVAtol(Atol, RiscV32SysVModel):
    pass


class RiscV32SysVAtoll(Atoll, RiscV32SysVModel):
    pass


class RiscV32SysVBsearch(Bsearch, RiscV32SysVModel):
    pass


class RiscV32SysVCalloc(Calloc, RiscV32SysVModel):
    pass


class RiscV32SysVDiv(Div, RiscV32SysVModel):
    pass


class RiscV32SysVLDiv(LDiv, RiscV32SysVModel):
    pass


class RiscV32SysVLLDiv(LLDiv, RiscV32SysVModel):
    pass


class RiscV32SysVExit(Exit, RiscV32SysVModel):
    pass


class RiscV32SysVFree(Free, RiscV32SysVModel):
    pass


class RiscV32SysVMalloc(Malloc, RiscV32SysVModel):
    pass


class RiscV32SysVQSort(QSort, RiscV32SysVModel):
    pass


class RiscV32SysVRand(Rand, RiscV32SysVModel):
    pass


class RiscV32SysVRealloc(Realloc, RiscV32SysVModel):
    pass


class RiscV32SysVSrand(Srand, RiscV32SysVModel):
    pass


class RiscV32SysVAbort(Abort, RiscV32SysVModel):
    pass


class RiscV32SysVAtexit(Atexit, RiscV32SysVModel):
    pass


class RiscV32SysVGetenv(Getenv, RiscV32SysVModel):
    pass


class RiscV32SysVMblen(Mblen, RiscV32SysVModel):
    pass


class RiscV32SysVMbstowcs(Mbstowcs, RiscV32SysVModel):
    pass


class RiscV32SysVMbtowc(Mbtowc, RiscV32SysVModel):
    pass


class RiscV32SysVSystem(System, RiscV32SysVModel):
    pass


class RiscV32SysVWcstombs(Wcstombs, RiscV32SysVModel):
    pass


class RiscV32SysVWctomb(Wctomb, RiscV32SysVModel):
    pass


__all__ = [
    "RiscV32SysVAbs",
    "RiscV32SysVLAbs",
    "RiscV32SysVLLAbs",
    "RiscV32SysVAtof",
    "RiscV32SysVAtoi",
    "RiscV32SysVAtol",
    "RiscV32SysVAtoll",
    "RiscV32SysVBsearch",
    "RiscV32SysVCalloc",
    "RiscV32SysVDiv",
    "RiscV32SysVLDiv",
    "RiscV32SysVLLDiv",
    "RiscV32SysVExit",
    "RiscV32SysVFree",
    "RiscV32SysVMalloc",
    "RiscV32SysVQSort",
    "RiscV32SysVRand",
    "RiscV32SysVRealloc",
    "RiscV32SysVSrand",
    "RiscV32SysVAbort",
    "RiscV32SysVAtexit",
    "RiscV32SysVGetenv",
    "RiscV32SysVMblen",
    "RiscV32SysVMbstowcs",
    "RiscV32SysVMbtowc",
    "RiscV32SysVSystem",
    "RiscV32SysVWcstombs",
    "RiscV32SysVWctomb",
]
