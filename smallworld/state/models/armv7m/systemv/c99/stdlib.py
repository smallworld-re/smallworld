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
from ..systemv import ArmV7MSysVModel


class ArmV7MSysVAbs(Abs, ArmV7MSysVModel):
    pass


class ArmV7MSysVLAbs(LAbs, ArmV7MSysVModel):
    pass


class ArmV7MSysVLLAbs(LLAbs, ArmV7MSysVModel):
    pass


class ArmV7MSysVAtof(Atof, ArmV7MSysVModel):
    pass


class ArmV7MSysVAtoi(Atoi, ArmV7MSysVModel):
    pass


class ArmV7MSysVAtol(Atol, ArmV7MSysVModel):
    pass


class ArmV7MSysVAtoll(Atoll, ArmV7MSysVModel):
    pass


class ArmV7MSysVBsearch(Bsearch, ArmV7MSysVModel):
    pass


class ArmV7MSysVCalloc(Calloc, ArmV7MSysVModel):
    pass


class ArmV7MSysVDiv(Div, ArmV7MSysVModel):
    pass


class ArmV7MSysVLDiv(LDiv, ArmV7MSysVModel):
    pass


class ArmV7MSysVLLDiv(LLDiv, ArmV7MSysVModel):
    pass


class ArmV7MSysVExit(Exit, ArmV7MSysVModel):
    pass


class ArmV7MSysVFree(Free, ArmV7MSysVModel):
    pass


class ArmV7MSysVMalloc(Malloc, ArmV7MSysVModel):
    pass


class ArmV7MSysVQSort(QSort, ArmV7MSysVModel):
    pass


class ArmV7MSysVRand(Rand, ArmV7MSysVModel):
    pass


class ArmV7MSysVRealloc(Realloc, ArmV7MSysVModel):
    pass


class ArmV7MSysVSrand(Srand, ArmV7MSysVModel):
    pass


class ArmV7MSysVAbort(Abort, ArmV7MSysVModel):
    pass


class ArmV7MSysVAtexit(Atexit, ArmV7MSysVModel):
    pass


class ArmV7MSysVGetenv(Getenv, ArmV7MSysVModel):
    pass


class ArmV7MSysVMblen(Mblen, ArmV7MSysVModel):
    pass


class ArmV7MSysVMbstowcs(Mbstowcs, ArmV7MSysVModel):
    pass


class ArmV7MSysVMbtowc(Mbtowc, ArmV7MSysVModel):
    pass


class ArmV7MSysVSystem(System, ArmV7MSysVModel):
    pass


class ArmV7MSysVWcstombs(Wcstombs, ArmV7MSysVModel):
    pass


class ArmV7MSysVWctomb(Wctomb, ArmV7MSysVModel):
    pass


__all__ = [
    "ArmV7MSysVAbs",
    "ArmV7MSysVLAbs",
    "ArmV7MSysVLLAbs",
    "ArmV7MSysVAtof",
    "ArmV7MSysVAtoi",
    "ArmV7MSysVAtol",
    "ArmV7MSysVAtoll",
    "ArmV7MSysVBsearch",
    "ArmV7MSysVCalloc",
    "ArmV7MSysVDiv",
    "ArmV7MSysVLDiv",
    "ArmV7MSysVLLDiv",
    "ArmV7MSysVExit",
    "ArmV7MSysVFree",
    "ArmV7MSysVMalloc",
    "ArmV7MSysVQSort",
    "ArmV7MSysVRand",
    "ArmV7MSysVRealloc",
    "ArmV7MSysVSrand",
    "ArmV7MSysVAbort",
    "ArmV7MSysVAtexit",
    "ArmV7MSysVGetenv",
    "ArmV7MSysVMblen",
    "ArmV7MSysVMbstowcs",
    "ArmV7MSysVMbtowc",
    "ArmV7MSysVSystem",
    "ArmV7MSysVWcstombs",
    "ArmV7MSysVWctomb",
]
