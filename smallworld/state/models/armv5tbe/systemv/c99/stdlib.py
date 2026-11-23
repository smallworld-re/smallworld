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
from ..systemv import ArmV5TBESysVModel


class ArmV5TBESysVAbs(Abs, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVLAbs(LAbs, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVLLAbs(LLAbs, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVAtof(Atof, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVAtoi(Atoi, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVAtol(Atol, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVAtoll(Atoll, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVBsearch(Bsearch, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVCalloc(Calloc, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVDiv(Div, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVLDiv(LDiv, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVLLDiv(LLDiv, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVExit(Exit, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVFree(Free, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVMalloc(Malloc, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVQSort(QSort, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVRand(Rand, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVRealloc(Realloc, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSrand(Srand, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVAbort(Abort, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVAtexit(Atexit, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVGetenv(Getenv, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVMblen(Mblen, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVMbstowcs(Mbstowcs, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVMbtowc(Mbtowc, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSystem(System, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVWcstombs(Wcstombs, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVWctomb(Wctomb, ArmV5TBESysVModel):
    pass


__all__ = [
    "ArmV5TBESysVAbs",
    "ArmV5TBESysVLAbs",
    "ArmV5TBESysVLLAbs",
    "ArmV5TBESysVAtof",
    "ArmV5TBESysVAtoi",
    "ArmV5TBESysVAtol",
    "ArmV5TBESysVAtoll",
    "ArmV5TBESysVBsearch",
    "ArmV5TBESysVCalloc",
    "ArmV5TBESysVDiv",
    "ArmV5TBESysVLDiv",
    "ArmV5TBESysVLLDiv",
    "ArmV5TBESysVExit",
    "ArmV5TBESysVFree",
    "ArmV5TBESysVMalloc",
    "ArmV5TBESysVQSort",
    "ArmV5TBESysVRand",
    "ArmV5TBESysVRealloc",
    "ArmV5TBESysVSrand",
    "ArmV5TBESysVAbort",
    "ArmV5TBESysVAtexit",
    "ArmV5TBESysVGetenv",
    "ArmV5TBESysVMblen",
    "ArmV5TBESysVMbstowcs",
    "ArmV5TBESysVMbtowc",
    "ArmV5TBESysVSystem",
    "ArmV5TBESysVWcstombs",
    "ArmV5TBESysVWctomb",
]
