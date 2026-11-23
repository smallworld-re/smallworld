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
from ..systemv import ArmV6MSysVModel


class ArmV6MSysVAbs(Abs, ArmV6MSysVModel):
    pass


class ArmV6MSysVLAbs(LAbs, ArmV6MSysVModel):
    pass


class ArmV6MSysVLLAbs(LLAbs, ArmV6MSysVModel):
    pass


class ArmV6MSysVAtof(Atof, ArmV6MSysVModel):
    pass


class ArmV6MSysVAtoi(Atoi, ArmV6MSysVModel):
    pass


class ArmV6MSysVAtol(Atol, ArmV6MSysVModel):
    pass


class ArmV6MSysVAtoll(Atoll, ArmV6MSysVModel):
    pass


class ArmV6MSysVBsearch(Bsearch, ArmV6MSysVModel):
    pass


class ArmV6MSysVCalloc(Calloc, ArmV6MSysVModel):
    pass


class ArmV6MSysVDiv(Div, ArmV6MSysVModel):
    pass


class ArmV6MSysVLDiv(LDiv, ArmV6MSysVModel):
    pass


class ArmV6MSysVLLDiv(LLDiv, ArmV6MSysVModel):
    pass


class ArmV6MSysVExit(Exit, ArmV6MSysVModel):
    pass


class ArmV6MSysVFree(Free, ArmV6MSysVModel):
    pass


class ArmV6MSysVMalloc(Malloc, ArmV6MSysVModel):
    pass


class ArmV6MSysVQSort(QSort, ArmV6MSysVModel):
    pass


class ArmV6MSysVRand(Rand, ArmV6MSysVModel):
    pass


class ArmV6MSysVRealloc(Realloc, ArmV6MSysVModel):
    pass


class ArmV6MSysVSrand(Srand, ArmV6MSysVModel):
    pass


class ArmV6MSysVAbort(Abort, ArmV6MSysVModel):
    pass


class ArmV6MSysVAtexit(Atexit, ArmV6MSysVModel):
    pass


class ArmV6MSysVGetenv(Getenv, ArmV6MSysVModel):
    pass


class ArmV6MSysVMblen(Mblen, ArmV6MSysVModel):
    pass


class ArmV6MSysVMbstowcs(Mbstowcs, ArmV6MSysVModel):
    pass


class ArmV6MSysVMbtowc(Mbtowc, ArmV6MSysVModel):
    pass


class ArmV6MSysVSystem(System, ArmV6MSysVModel):
    pass


class ArmV6MSysVWcstombs(Wcstombs, ArmV6MSysVModel):
    pass


class ArmV6MSysVWctomb(Wctomb, ArmV6MSysVModel):
    pass


__all__ = [
    "ArmV6MSysVAbs",
    "ArmV6MSysVLAbs",
    "ArmV6MSysVLLAbs",
    "ArmV6MSysVAtof",
    "ArmV6MSysVAtoi",
    "ArmV6MSysVAtol",
    "ArmV6MSysVAtoll",
    "ArmV6MSysVBsearch",
    "ArmV6MSysVCalloc",
    "ArmV6MSysVDiv",
    "ArmV6MSysVLDiv",
    "ArmV6MSysVLLDiv",
    "ArmV6MSysVExit",
    "ArmV6MSysVFree",
    "ArmV6MSysVMalloc",
    "ArmV6MSysVQSort",
    "ArmV6MSysVRand",
    "ArmV6MSysVRealloc",
    "ArmV6MSysVSrand",
    "ArmV6MSysVAbort",
    "ArmV6MSysVAtexit",
    "ArmV6MSysVGetenv",
    "ArmV6MSysVMblen",
    "ArmV6MSysVMbstowcs",
    "ArmV6MSysVMbtowc",
    "ArmV6MSysVSystem",
    "ArmV6MSysVWcstombs",
    "ArmV6MSysVWctomb",
]
