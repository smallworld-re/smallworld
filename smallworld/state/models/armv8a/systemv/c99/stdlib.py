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
from ..systemv import ArmV8ASysVModel


class ArmV8ASysVAbs(Abs, ArmV8ASysVModel):
    pass


class ArmV8ASysVLAbs(LAbs, ArmV8ASysVModel):
    pass


class ArmV8ASysVLLAbs(LLAbs, ArmV8ASysVModel):
    pass


class ArmV8ASysVAtof(Atof, ArmV8ASysVModel):
    pass


class ArmV8ASysVAtoi(Atoi, ArmV8ASysVModel):
    pass


class ArmV8ASysVAtol(Atol, ArmV8ASysVModel):
    pass


class ArmV8ASysVAtoll(Atoll, ArmV8ASysVModel):
    pass


class ArmV8ASysVBsearch(Bsearch, ArmV8ASysVModel):
    pass


class ArmV8ASysVCalloc(Calloc, ArmV8ASysVModel):
    pass


class ArmV8ASysVDiv(Div, ArmV8ASysVModel):
    pass


class ArmV8ASysVLDiv(LDiv, ArmV8ASysVModel):
    pass


class ArmV8ASysVLLDiv(LLDiv, ArmV8ASysVModel):
    pass


class ArmV8ASysVExit(Exit, ArmV8ASysVModel):
    pass


class ArmV8ASysVFree(Free, ArmV8ASysVModel):
    pass


class ArmV8ASysVMalloc(Malloc, ArmV8ASysVModel):
    pass


class ArmV8ASysVQSort(QSort, ArmV8ASysVModel):
    pass


class ArmV8ASysVRand(Rand, ArmV8ASysVModel):
    pass


class ArmV8ASysVRealloc(Realloc, ArmV8ASysVModel):
    pass


class ArmV8ASysVSrand(Srand, ArmV8ASysVModel):
    pass


class ArmV8ASysVAbort(Abort, ArmV8ASysVModel):
    pass


class ArmV8ASysVAtexit(Atexit, ArmV8ASysVModel):
    pass


class ArmV8ASysVGetenv(Getenv, ArmV8ASysVModel):
    pass


class ArmV8ASysVMblen(Mblen, ArmV8ASysVModel):
    pass


class ArmV8ASysVMbstowcs(Mbstowcs, ArmV8ASysVModel):
    pass


class ArmV8ASysVMbtowc(Mbtowc, ArmV8ASysVModel):
    pass


class ArmV8ASysVSystem(System, ArmV8ASysVModel):
    pass


class ArmV8ASysVWcstombs(Wcstombs, ArmV8ASysVModel):
    pass


class ArmV8ASysVWctomb(Wctomb, ArmV8ASysVModel):
    pass


__all__ = [
    "ArmV8ASysVAbs",
    "ArmV8ASysVLAbs",
    "ArmV8ASysVLLAbs",
    "ArmV8ASysVAtof",
    "ArmV8ASysVAtoi",
    "ArmV8ASysVAtol",
    "ArmV8ASysVAtoll",
    "ArmV8ASysVBsearch",
    "ArmV8ASysVCalloc",
    "ArmV8ASysVDiv",
    "ArmV8ASysVLDiv",
    "ArmV8ASysVLLDiv",
    "ArmV8ASysVExit",
    "ArmV8ASysVFree",
    "ArmV8ASysVMalloc",
    "ArmV8ASysVQSort",
    "ArmV8ASysVRand",
    "ArmV8ASysVRealloc",
    "ArmV8ASysVSrand",
    "ArmV8ASysVAbort",
    "ArmV8ASysVAtexit",
    "ArmV8ASysVGetenv",
    "ArmV8ASysVMblen",
    "ArmV8ASysVMbstowcs",
    "ArmV8ASysVMbtowc",
    "ArmV8ASysVSystem",
    "ArmV8ASysVWcstombs",
    "ArmV8ASysVWctomb",
]
