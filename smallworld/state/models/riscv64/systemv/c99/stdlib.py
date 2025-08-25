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
from ..systemv import RiscV64SysVModel


class RiscV64SysVAbs(Abs, RiscV64SysVModel):
    pass


class RiscV64SysVLAbs(LAbs, RiscV64SysVModel):
    pass


class RiscV64SysVLLAbs(LLAbs, RiscV64SysVModel):
    pass


class RiscV64SysVAtof(Atof, RiscV64SysVModel):
    pass


class RiscV64SysVAtoi(Atoi, RiscV64SysVModel):
    pass


class RiscV64SysVAtol(Atol, RiscV64SysVModel):
    pass


class RiscV64SysVAtoll(Atoll, RiscV64SysVModel):
    pass


class RiscV64SysVCalloc(Calloc, RiscV64SysVModel):
    pass


class RiscV64SysVDiv(Div, RiscV64SysVModel):
    pass


class RiscV64SysVLDiv(LDiv, RiscV64SysVModel):
    pass


class RiscV64SysVLLDiv(LLDiv, RiscV64SysVModel):
    pass


class RiscV64SysVExit(Exit, RiscV64SysVModel):
    pass


class RiscV64SysVFree(Free, RiscV64SysVModel):
    pass


class RiscV64SysVMalloc(Malloc, RiscV64SysVModel):
    pass


class RiscV64SysVQSort(QSort, RiscV64SysVModel):
    pass


class RiscV64SysVRand(Rand, RiscV64SysVModel):
    pass


class RiscV64SysVRealloc(Realloc, RiscV64SysVModel):
    pass


class RiscV64SysVSrand(Srand, RiscV64SysVModel):
    pass


class RiscV64SysVAbort(Abort, RiscV64SysVModel):
    pass


class RiscV64SysVAtexit(Atexit, RiscV64SysVModel):
    pass


class RiscV64SysVGetenv(Getenv, RiscV64SysVModel):
    pass


class RiscV64SysVMblen(Mblen, RiscV64SysVModel):
    pass


class RiscV64SysVMbstowcs(Mbstowcs, RiscV64SysVModel):
    pass


class RiscV64SysVMbtowc(Mbtowc, RiscV64SysVModel):
    pass


class RiscV64SysVSystem(System, RiscV64SysVModel):
    pass


class RiscV64SysVWcstombs(Wcstombs, RiscV64SysVModel):
    pass


class RiscV64SysVWctomb(Wctomb, RiscV64SysVModel):
    pass


__all__ = [
    "RiscV64SysVAbs",
    "RiscV64SysVLAbs",
    "RiscV64SysVLLAbs",
    "RiscV64SysVAtof",
    "RiscV64SysVAtoi",
    "RiscV64SysVAtol",
    "RiscV64SysVAtoll",
    "RiscV64SysVCalloc",
    "RiscV64SysVDiv",
    "RiscV64SysVLDiv",
    "RiscV64SysVLLDiv",
    "RiscV64SysVExit",
    "RiscV64SysVFree",
    "RiscV64SysVMalloc",
    "RiscV64SysVQSort",
    "RiscV64SysVRand",
    "RiscV64SysVRealloc",
    "RiscV64SysVSrand",
    "RiscV64SysVAbort",
    "RiscV64SysVAtexit",
    "RiscV64SysVGetenv",
    "RiscV64SysVMblen",
    "RiscV64SysVMbstowcs",
    "RiscV64SysVMbtowc",
    "RiscV64SysVSystem",
    "RiscV64SysVWcstombs",
    "RiscV64SysVWctomb",
]
