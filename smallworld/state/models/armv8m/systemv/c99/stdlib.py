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
from ..systemv import ArmV8MSysVModel


class ArmV8MSysVAbs(Abs, ArmV8MSysVModel):
    pass


class ArmV8MSysVLAbs(LAbs, ArmV8MSysVModel):
    pass


class ArmV8MSysVLLAbs(LLAbs, ArmV8MSysVModel):
    pass


class ArmV8MSysVAtof(Atof, ArmV8MSysVModel):
    pass


class ArmV8MSysVAtoi(Atoi, ArmV8MSysVModel):
    pass


class ArmV8MSysVAtol(Atol, ArmV8MSysVModel):
    pass


class ArmV8MSysVAtoll(Atoll, ArmV8MSysVModel):
    pass


class ArmV8MSysVBsearch(Bsearch, ArmV8MSysVModel):
    pass


class ArmV8MSysVCalloc(Calloc, ArmV8MSysVModel):
    pass


class ArmV8MSysVDiv(Div, ArmV8MSysVModel):
    pass


class ArmV8MSysVLDiv(LDiv, ArmV8MSysVModel):
    pass


class ArmV8MSysVLLDiv(LLDiv, ArmV8MSysVModel):
    pass


class ArmV8MSysVExit(Exit, ArmV8MSysVModel):
    pass


class ArmV8MSysVFree(Free, ArmV8MSysVModel):
    pass


class ArmV8MSysVMalloc(Malloc, ArmV8MSysVModel):
    pass


class ArmV8MSysVQSort(QSort, ArmV8MSysVModel):
    pass


class ArmV8MSysVRand(Rand, ArmV8MSysVModel):
    pass


class ArmV8MSysVRealloc(Realloc, ArmV8MSysVModel):
    pass


class ArmV8MSysVSrand(Srand, ArmV8MSysVModel):
    pass


class ArmV8MSysVAbort(Abort, ArmV8MSysVModel):
    pass


class ArmV8MSysVAtexit(Atexit, ArmV8MSysVModel):
    pass


class ArmV8MSysVGetenv(Getenv, ArmV8MSysVModel):
    pass


class ArmV8MSysVMblen(Mblen, ArmV8MSysVModel):
    pass


class ArmV8MSysVMbstowcs(Mbstowcs, ArmV8MSysVModel):
    pass


class ArmV8MSysVMbtowc(Mbtowc, ArmV8MSysVModel):
    pass


class ArmV8MSysVSystem(System, ArmV8MSysVModel):
    pass


class ArmV8MSysVWcstombs(Wcstombs, ArmV8MSysVModel):
    pass


class ArmV8MSysVWctomb(Wctomb, ArmV8MSysVModel):
    pass


__all__ = [
    "ArmV8MSysVAbs",
    "ArmV8MSysVLAbs",
    "ArmV8MSysVLLAbs",
    "ArmV8MSysVAtof",
    "ArmV8MSysVAtoi",
    "ArmV8MSysVAtol",
    "ArmV8MSysVAtoll",
    "ArmV8MSysVBsearch",
    "ArmV8MSysVCalloc",
    "ArmV8MSysVDiv",
    "ArmV8MSysVLDiv",
    "ArmV8MSysVLLDiv",
    "ArmV8MSysVExit",
    "ArmV8MSysVFree",
    "ArmV8MSysVMalloc",
    "ArmV8MSysVQSort",
    "ArmV8MSysVRand",
    "ArmV8MSysVRealloc",
    "ArmV8MSysVSrand",
    "ArmV8MSysVAbort",
    "ArmV8MSysVAtexit",
    "ArmV8MSysVGetenv",
    "ArmV8MSysVMblen",
    "ArmV8MSysVMbstowcs",
    "ArmV8MSysVMbtowc",
    "ArmV8MSysVSystem",
    "ArmV8MSysVWcstombs",
    "ArmV8MSysVWctomb",
]
