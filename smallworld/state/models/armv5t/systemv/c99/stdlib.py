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
from ..systemv import ArmV5TSysVModel


class ArmV5TSysVAbs(Abs, ArmV5TSysVModel):
    pass


class ArmV5TSysVLAbs(LAbs, ArmV5TSysVModel):
    pass


class ArmV5TSysVLLAbs(LLAbs, ArmV5TSysVModel):
    pass


class ArmV5TSysVAtof(Atof, ArmV5TSysVModel):
    pass


class ArmV5TSysVAtoi(Atoi, ArmV5TSysVModel):
    pass


class ArmV5TSysVAtol(Atol, ArmV5TSysVModel):
    pass


class ArmV5TSysVAtoll(Atoll, ArmV5TSysVModel):
    pass


class ArmV5TSysVBsearch(Bsearch, ArmV5TSysVModel):
    pass


class ArmV5TSysVCalloc(Calloc, ArmV5TSysVModel):
    pass


class ArmV5TSysVDiv(Div, ArmV5TSysVModel):
    pass


class ArmV5TSysVLDiv(LDiv, ArmV5TSysVModel):
    pass


class ArmV5TSysVLLDiv(LLDiv, ArmV5TSysVModel):
    pass


class ArmV5TSysVExit(Exit, ArmV5TSysVModel):
    pass


class ArmV5TSysVFree(Free, ArmV5TSysVModel):
    pass


class ArmV5TSysVMalloc(Malloc, ArmV5TSysVModel):
    pass


class ArmV5TSysVQSort(QSort, ArmV5TSysVModel):
    pass


class ArmV5TSysVRand(Rand, ArmV5TSysVModel):
    pass


class ArmV5TSysVRealloc(Realloc, ArmV5TSysVModel):
    pass


class ArmV5TSysVSrand(Srand, ArmV5TSysVModel):
    pass


class ArmV5TSysVAbort(Abort, ArmV5TSysVModel):
    pass


class ArmV5TSysVAtexit(Atexit, ArmV5TSysVModel):
    pass


class ArmV5TSysVGetenv(Getenv, ArmV5TSysVModel):
    pass


class ArmV5TSysVMblen(Mblen, ArmV5TSysVModel):
    pass


class ArmV5TSysVMbstowcs(Mbstowcs, ArmV5TSysVModel):
    pass


class ArmV5TSysVMbtowc(Mbtowc, ArmV5TSysVModel):
    pass


class ArmV5TSysVSystem(System, ArmV5TSysVModel):
    pass


class ArmV5TSysVWcstombs(Wcstombs, ArmV5TSysVModel):
    pass


class ArmV5TSysVWctomb(Wctomb, ArmV5TSysVModel):
    pass


__all__ = [
    "ArmV5TSysVAbs",
    "ArmV5TSysVLAbs",
    "ArmV5TSysVLLAbs",
    "ArmV5TSysVAtof",
    "ArmV5TSysVAtoi",
    "ArmV5TSysVAtol",
    "ArmV5TSysVAtoll",
    "ArmV5TSysVBsearch",
    "ArmV5TSysVCalloc",
    "ArmV5TSysVDiv",
    "ArmV5TSysVLDiv",
    "ArmV5TSysVLLDiv",
    "ArmV5TSysVExit",
    "ArmV5TSysVFree",
    "ArmV5TSysVMalloc",
    "ArmV5TSysVQSort",
    "ArmV5TSysVRand",
    "ArmV5TSysVRealloc",
    "ArmV5TSysVSrand",
    "ArmV5TSysVAbort",
    "ArmV5TSysVAtexit",
    "ArmV5TSysVGetenv",
    "ArmV5TSysVMblen",
    "ArmV5TSysVMbstowcs",
    "ArmV5TSysVMbtowc",
    "ArmV5TSysVSystem",
    "ArmV5TSysVWcstombs",
    "ArmV5TSysVWctomb",
]
