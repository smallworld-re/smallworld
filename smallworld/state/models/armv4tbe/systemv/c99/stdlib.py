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
from ..systemv import ArmV4TBESysVModel


class ArmV4TBESysVAbs(Abs, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVLAbs(LAbs, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVLLAbs(LLAbs, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVAtof(Atof, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVAtoi(Atoi, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVAtol(Atol, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVAtoll(Atoll, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVBsearch(Bsearch, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVCalloc(Calloc, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVDiv(Div, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVLDiv(LDiv, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVLLDiv(LLDiv, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVExit(Exit, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVFree(Free, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVMalloc(Malloc, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVQSort(QSort, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVRand(Rand, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVRealloc(Realloc, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSrand(Srand, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVAbort(Abort, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVAtexit(Atexit, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVGetenv(Getenv, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVMblen(Mblen, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVMbstowcs(Mbstowcs, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVMbtowc(Mbtowc, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSystem(System, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVWcstombs(Wcstombs, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVWctomb(Wctomb, ArmV4TBESysVModel):
    pass


__all__ = [
    "ArmV4TBESysVAbs",
    "ArmV4TBESysVLAbs",
    "ArmV4TBESysVLLAbs",
    "ArmV4TBESysVAtof",
    "ArmV4TBESysVAtoi",
    "ArmV4TBESysVAtol",
    "ArmV4TBESysVAtoll",
    "ArmV4TBESysVBsearch",
    "ArmV4TBESysVCalloc",
    "ArmV4TBESysVDiv",
    "ArmV4TBESysVLDiv",
    "ArmV4TBESysVLLDiv",
    "ArmV4TBESysVExit",
    "ArmV4TBESysVFree",
    "ArmV4TBESysVMalloc",
    "ArmV4TBESysVQSort",
    "ArmV4TBESysVRand",
    "ArmV4TBESysVRealloc",
    "ArmV4TBESysVSrand",
    "ArmV4TBESysVAbort",
    "ArmV4TBESysVAtexit",
    "ArmV4TBESysVGetenv",
    "ArmV4TBESysVMblen",
    "ArmV4TBESysVMbstowcs",
    "ArmV4TBESysVMbtowc",
    "ArmV4TBESysVSystem",
    "ArmV4TBESysVWcstombs",
    "ArmV4TBESysVWctomb",
]
