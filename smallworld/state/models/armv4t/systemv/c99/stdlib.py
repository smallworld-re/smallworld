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
from ..systemv import ArmV4TSysVModel


class ArmV4TSysVAbs(Abs, ArmV4TSysVModel):
    pass


class ArmV4TSysVLAbs(LAbs, ArmV4TSysVModel):
    pass


class ArmV4TSysVLLAbs(LLAbs, ArmV4TSysVModel):
    pass


class ArmV4TSysVAtof(Atof, ArmV4TSysVModel):
    pass


class ArmV4TSysVAtoi(Atoi, ArmV4TSysVModel):
    pass


class ArmV4TSysVAtol(Atol, ArmV4TSysVModel):
    pass


class ArmV4TSysVAtoll(Atoll, ArmV4TSysVModel):
    pass


class ArmV4TSysVBsearch(Bsearch, ArmV4TSysVModel):
    pass


class ArmV4TSysVCalloc(Calloc, ArmV4TSysVModel):
    pass


class ArmV4TSysVDiv(Div, ArmV4TSysVModel):
    pass


class ArmV4TSysVLDiv(LDiv, ArmV4TSysVModel):
    pass


class ArmV4TSysVLLDiv(LLDiv, ArmV4TSysVModel):
    pass


class ArmV4TSysVExit(Exit, ArmV4TSysVModel):
    pass


class ArmV4TSysVFree(Free, ArmV4TSysVModel):
    pass


class ArmV4TSysVMalloc(Malloc, ArmV4TSysVModel):
    pass


class ArmV4TSysVQSort(QSort, ArmV4TSysVModel):
    pass


class ArmV4TSysVRand(Rand, ArmV4TSysVModel):
    pass


class ArmV4TSysVRealloc(Realloc, ArmV4TSysVModel):
    pass


class ArmV4TSysVSrand(Srand, ArmV4TSysVModel):
    pass


class ArmV4TSysVAbort(Abort, ArmV4TSysVModel):
    pass


class ArmV4TSysVAtexit(Atexit, ArmV4TSysVModel):
    pass


class ArmV4TSysVGetenv(Getenv, ArmV4TSysVModel):
    pass


class ArmV4TSysVMblen(Mblen, ArmV4TSysVModel):
    pass


class ArmV4TSysVMbstowcs(Mbstowcs, ArmV4TSysVModel):
    pass


class ArmV4TSysVMbtowc(Mbtowc, ArmV4TSysVModel):
    pass


class ArmV4TSysVSystem(System, ArmV4TSysVModel):
    pass


class ArmV4TSysVWcstombs(Wcstombs, ArmV4TSysVModel):
    pass


class ArmV4TSysVWctomb(Wctomb, ArmV4TSysVModel):
    pass


__all__ = [
    "ArmV4TSysVAbs",
    "ArmV4TSysVLAbs",
    "ArmV4TSysVLLAbs",
    "ArmV4TSysVAtof",
    "ArmV4TSysVAtoi",
    "ArmV4TSysVAtol",
    "ArmV4TSysVAtoll",
    "ArmV4TSysVBsearch",
    "ArmV4TSysVCalloc",
    "ArmV4TSysVDiv",
    "ArmV4TSysVLDiv",
    "ArmV4TSysVLLDiv",
    "ArmV4TSysVExit",
    "ArmV4TSysVFree",
    "ArmV4TSysVMalloc",
    "ArmV4TSysVQSort",
    "ArmV4TSysVRand",
    "ArmV4TSysVRealloc",
    "ArmV4TSysVSrand",
    "ArmV4TSysVAbort",
    "ArmV4TSysVAtexit",
    "ArmV4TSysVGetenv",
    "ArmV4TSysVMblen",
    "ArmV4TSysVMbstowcs",
    "ArmV4TSysVMbtowc",
    "ArmV4TSysVSystem",
    "ArmV4TSysVWcstombs",
    "ArmV4TSysVWctomb",
]
