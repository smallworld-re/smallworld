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
from ..systemv import ArmV7EMSysVModel


class ArmV7EMSysVAbs(Abs, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVLAbs(LAbs, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVLLAbs(LLAbs, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVAtof(Atof, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVAtoi(Atoi, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVAtol(Atol, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVAtoll(Atoll, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVBsearch(Bsearch, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVCalloc(Calloc, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVDiv(Div, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVLDiv(LDiv, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVLLDiv(LLDiv, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVExit(Exit, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVFree(Free, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVMalloc(Malloc, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVQSort(QSort, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVRand(Rand, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVRealloc(Realloc, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSrand(Srand, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVAbort(Abort, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVAtexit(Atexit, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVGetenv(Getenv, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVMblen(Mblen, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVMbstowcs(Mbstowcs, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVMbtowc(Mbtowc, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSystem(System, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVWcstombs(Wcstombs, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVWctomb(Wctomb, ArmV7EMSysVModel):
    pass


__all__ = [
    "ArmV7EMSysVAbs",
    "ArmV7EMSysVLAbs",
    "ArmV7EMSysVLLAbs",
    "ArmV7EMSysVAtof",
    "ArmV7EMSysVAtoi",
    "ArmV7EMSysVAtol",
    "ArmV7EMSysVAtoll",
    "ArmV7EMSysVBsearch",
    "ArmV7EMSysVCalloc",
    "ArmV7EMSysVDiv",
    "ArmV7EMSysVLDiv",
    "ArmV7EMSysVLLDiv",
    "ArmV7EMSysVExit",
    "ArmV7EMSysVFree",
    "ArmV7EMSysVMalloc",
    "ArmV7EMSysVQSort",
    "ArmV7EMSysVRand",
    "ArmV7EMSysVRealloc",
    "ArmV7EMSysVSrand",
    "ArmV7EMSysVAbort",
    "ArmV7EMSysVAtexit",
    "ArmV7EMSysVGetenv",
    "ArmV7EMSysVMblen",
    "ArmV7EMSysVMbstowcs",
    "ArmV7EMSysVMbtowc",
    "ArmV7EMSysVSystem",
    "ArmV7EMSysVWcstombs",
    "ArmV7EMSysVWctomb",
]
