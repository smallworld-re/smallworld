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
from ..systemv import ArmV7RSysVModel


class ArmV7RSysVAbs(Abs, ArmV7RSysVModel):
    pass


class ArmV7RSysVLAbs(LAbs, ArmV7RSysVModel):
    pass


class ArmV7RSysVLLAbs(LLAbs, ArmV7RSysVModel):
    pass


class ArmV7RSysVAtof(Atof, ArmV7RSysVModel):
    pass


class ArmV7RSysVAtoi(Atoi, ArmV7RSysVModel):
    pass


class ArmV7RSysVAtol(Atol, ArmV7RSysVModel):
    pass


class ArmV7RSysVAtoll(Atoll, ArmV7RSysVModel):
    pass


class ArmV7RSysVBsearch(Bsearch, ArmV7RSysVModel):
    pass


class ArmV7RSysVCalloc(Calloc, ArmV7RSysVModel):
    pass


class ArmV7RSysVDiv(Div, ArmV7RSysVModel):
    pass


class ArmV7RSysVLDiv(LDiv, ArmV7RSysVModel):
    pass


class ArmV7RSysVLLDiv(LLDiv, ArmV7RSysVModel):
    pass


class ArmV7RSysVExit(Exit, ArmV7RSysVModel):
    pass


class ArmV7RSysVFree(Free, ArmV7RSysVModel):
    pass


class ArmV7RSysVMalloc(Malloc, ArmV7RSysVModel):
    pass


class ArmV7RSysVQSort(QSort, ArmV7RSysVModel):
    pass


class ArmV7RSysVRand(Rand, ArmV7RSysVModel):
    pass


class ArmV7RSysVRealloc(Realloc, ArmV7RSysVModel):
    pass


class ArmV7RSysVSrand(Srand, ArmV7RSysVModel):
    pass


class ArmV7RSysVAbort(Abort, ArmV7RSysVModel):
    pass


class ArmV7RSysVAtexit(Atexit, ArmV7RSysVModel):
    pass


class ArmV7RSysVGetenv(Getenv, ArmV7RSysVModel):
    pass


class ArmV7RSysVMblen(Mblen, ArmV7RSysVModel):
    pass


class ArmV7RSysVMbstowcs(Mbstowcs, ArmV7RSysVModel):
    pass


class ArmV7RSysVMbtowc(Mbtowc, ArmV7RSysVModel):
    pass


class ArmV7RSysVSystem(System, ArmV7RSysVModel):
    pass


class ArmV7RSysVWcstombs(Wcstombs, ArmV7RSysVModel):
    pass


class ArmV7RSysVWctomb(Wctomb, ArmV7RSysVModel):
    pass


__all__ = [
    "ArmV7RSysVAbs",
    "ArmV7RSysVLAbs",
    "ArmV7RSysVLLAbs",
    "ArmV7RSysVAtof",
    "ArmV7RSysVAtoi",
    "ArmV7RSysVAtol",
    "ArmV7RSysVAtoll",
    "ArmV7RSysVBsearch",
    "ArmV7RSysVCalloc",
    "ArmV7RSysVDiv",
    "ArmV7RSysVLDiv",
    "ArmV7RSysVLLDiv",
    "ArmV7RSysVExit",
    "ArmV7RSysVFree",
    "ArmV7RSysVMalloc",
    "ArmV7RSysVQSort",
    "ArmV7RSysVRand",
    "ArmV7RSysVRealloc",
    "ArmV7RSysVSrand",
    "ArmV7RSysVAbort",
    "ArmV7RSysVAtexit",
    "ArmV7RSysVGetenv",
    "ArmV7RSysVMblen",
    "ArmV7RSysVMbstowcs",
    "ArmV7RSysVMbtowc",
    "ArmV7RSysVSystem",
    "ArmV7RSysVWcstombs",
    "ArmV7RSysVWctomb",
]
