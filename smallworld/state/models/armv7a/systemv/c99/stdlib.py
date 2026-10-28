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
from ..systemv import ArmV7ASysVModel


class ArmV7ASysVAbs(Abs, ArmV7ASysVModel):
    pass


class ArmV7ASysVLAbs(LAbs, ArmV7ASysVModel):
    pass


class ArmV7ASysVLLAbs(LLAbs, ArmV7ASysVModel):
    pass


class ArmV7ASysVAtof(Atof, ArmV7ASysVModel):
    pass


class ArmV7ASysVAtoi(Atoi, ArmV7ASysVModel):
    pass


class ArmV7ASysVAtol(Atol, ArmV7ASysVModel):
    pass


class ArmV7ASysVAtoll(Atoll, ArmV7ASysVModel):
    pass


class ArmV7ASysVBsearch(Bsearch, ArmV7ASysVModel):
    pass


class ArmV7ASysVCalloc(Calloc, ArmV7ASysVModel):
    pass


class ArmV7ASysVDiv(Div, ArmV7ASysVModel):
    pass


class ArmV7ASysVLDiv(LDiv, ArmV7ASysVModel):
    pass


class ArmV7ASysVLLDiv(LLDiv, ArmV7ASysVModel):
    pass


class ArmV7ASysVExit(Exit, ArmV7ASysVModel):
    pass


class ArmV7ASysVFree(Free, ArmV7ASysVModel):
    pass


class ArmV7ASysVMalloc(Malloc, ArmV7ASysVModel):
    pass


class ArmV7ASysVQSort(QSort, ArmV7ASysVModel):
    pass


class ArmV7ASysVRand(Rand, ArmV7ASysVModel):
    pass


class ArmV7ASysVRealloc(Realloc, ArmV7ASysVModel):
    pass


class ArmV7ASysVSrand(Srand, ArmV7ASysVModel):
    pass


class ArmV7ASysVAbort(Abort, ArmV7ASysVModel):
    pass


class ArmV7ASysVAtexit(Atexit, ArmV7ASysVModel):
    pass


class ArmV7ASysVGetenv(Getenv, ArmV7ASysVModel):
    pass


class ArmV7ASysVMblen(Mblen, ArmV7ASysVModel):
    pass


class ArmV7ASysVMbstowcs(Mbstowcs, ArmV7ASysVModel):
    pass


class ArmV7ASysVMbtowc(Mbtowc, ArmV7ASysVModel):
    pass


class ArmV7ASysVSystem(System, ArmV7ASysVModel):
    pass


class ArmV7ASysVWcstombs(Wcstombs, ArmV7ASysVModel):
    pass


class ArmV7ASysVWctomb(Wctomb, ArmV7ASysVModel):
    pass


__all__ = [
    "ArmV7ASysVAbs",
    "ArmV7ASysVLAbs",
    "ArmV7ASysVLLAbs",
    "ArmV7ASysVAtof",
    "ArmV7ASysVAtoi",
    "ArmV7ASysVAtol",
    "ArmV7ASysVAtoll",
    "ArmV7ASysVBsearch",
    "ArmV7ASysVCalloc",
    "ArmV7ASysVDiv",
    "ArmV7ASysVLDiv",
    "ArmV7ASysVLLDiv",
    "ArmV7ASysVExit",
    "ArmV7ASysVFree",
    "ArmV7ASysVMalloc",
    "ArmV7ASysVQSort",
    "ArmV7ASysVRand",
    "ArmV7ASysVRealloc",
    "ArmV7ASysVSrand",
    "ArmV7ASysVAbort",
    "ArmV7ASysVAtexit",
    "ArmV7ASysVGetenv",
    "ArmV7ASysVMblen",
    "ArmV7ASysVMbstowcs",
    "ArmV7ASysVMbtowc",
    "ArmV7ASysVSystem",
    "ArmV7ASysVWcstombs",
    "ArmV7ASysVWctomb",
]
