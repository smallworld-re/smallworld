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
from ..systemv import ArmV6KSysVModel


class ArmV6KSysVAbs(Abs, ArmV6KSysVModel):
    pass


class ArmV6KSysVLAbs(LAbs, ArmV6KSysVModel):
    pass


class ArmV6KSysVLLAbs(LLAbs, ArmV6KSysVModel):
    pass


class ArmV6KSysVAtof(Atof, ArmV6KSysVModel):
    pass


class ArmV6KSysVAtoi(Atoi, ArmV6KSysVModel):
    pass


class ArmV6KSysVAtol(Atol, ArmV6KSysVModel):
    pass


class ArmV6KSysVAtoll(Atoll, ArmV6KSysVModel):
    pass


class ArmV6KSysVBsearch(Bsearch, ArmV6KSysVModel):
    pass


class ArmV6KSysVCalloc(Calloc, ArmV6KSysVModel):
    pass


class ArmV6KSysVDiv(Div, ArmV6KSysVModel):
    pass


class ArmV6KSysVLDiv(LDiv, ArmV6KSysVModel):
    pass


class ArmV6KSysVLLDiv(LLDiv, ArmV6KSysVModel):
    pass


class ArmV6KSysVExit(Exit, ArmV6KSysVModel):
    pass


class ArmV6KSysVFree(Free, ArmV6KSysVModel):
    pass


class ArmV6KSysVMalloc(Malloc, ArmV6KSysVModel):
    pass


class ArmV6KSysVQSort(QSort, ArmV6KSysVModel):
    pass


class ArmV6KSysVRand(Rand, ArmV6KSysVModel):
    pass


class ArmV6KSysVRealloc(Realloc, ArmV6KSysVModel):
    pass


class ArmV6KSysVSrand(Srand, ArmV6KSysVModel):
    pass


class ArmV6KSysVAbort(Abort, ArmV6KSysVModel):
    pass


class ArmV6KSysVAtexit(Atexit, ArmV6KSysVModel):
    pass


class ArmV6KSysVGetenv(Getenv, ArmV6KSysVModel):
    pass


class ArmV6KSysVMblen(Mblen, ArmV6KSysVModel):
    pass


class ArmV6KSysVMbstowcs(Mbstowcs, ArmV6KSysVModel):
    pass


class ArmV6KSysVMbtowc(Mbtowc, ArmV6KSysVModel):
    pass


class ArmV6KSysVSystem(System, ArmV6KSysVModel):
    pass


class ArmV6KSysVWcstombs(Wcstombs, ArmV6KSysVModel):
    pass


class ArmV6KSysVWctomb(Wctomb, ArmV6KSysVModel):
    pass


__all__ = [
    "ArmV6KSysVAbs",
    "ArmV6KSysVLAbs",
    "ArmV6KSysVLLAbs",
    "ArmV6KSysVAtof",
    "ArmV6KSysVAtoi",
    "ArmV6KSysVAtol",
    "ArmV6KSysVAtoll",
    "ArmV6KSysVBsearch",
    "ArmV6KSysVCalloc",
    "ArmV6KSysVDiv",
    "ArmV6KSysVLDiv",
    "ArmV6KSysVLLDiv",
    "ArmV6KSysVExit",
    "ArmV6KSysVFree",
    "ArmV6KSysVMalloc",
    "ArmV6KSysVQSort",
    "ArmV6KSysVRand",
    "ArmV6KSysVRealloc",
    "ArmV6KSysVSrand",
    "ArmV6KSysVAbort",
    "ArmV6KSysVAtexit",
    "ArmV6KSysVGetenv",
    "ArmV6KSysVMblen",
    "ArmV6KSysVMbstowcs",
    "ArmV6KSysVMbtowc",
    "ArmV6KSysVSystem",
    "ArmV6KSysVWcstombs",
    "ArmV6KSysVWctomb",
]
