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
from ..systemv import ArmV8ABESysVModel


class ArmV8ABESysVAbs(Abs, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVLAbs(LAbs, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVLLAbs(LLAbs, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVAtof(Atof, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVAtoi(Atoi, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVAtol(Atol, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVAtoll(Atoll, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVBsearch(Bsearch, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVCalloc(Calloc, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVDiv(Div, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVLDiv(LDiv, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVLLDiv(LLDiv, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVExit(Exit, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVFree(Free, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVMalloc(Malloc, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVQSort(QSort, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVRand(Rand, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVRealloc(Realloc, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSrand(Srand, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVAbort(Abort, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVAtexit(Atexit, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVGetenv(Getenv, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVMblen(Mblen, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVMbstowcs(Mbstowcs, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVMbtowc(Mbtowc, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSystem(System, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVWcstombs(Wcstombs, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVWctomb(Wctomb, ArmV8ABESysVModel):
    pass


__all__ = [
    "ArmV8ABESysVAbs",
    "ArmV8ABESysVLAbs",
    "ArmV8ABESysVLLAbs",
    "ArmV8ABESysVAtof",
    "ArmV8ABESysVAtoi",
    "ArmV8ABESysVAtol",
    "ArmV8ABESysVAtoll",
    "ArmV8ABESysVBsearch",
    "ArmV8ABESysVCalloc",
    "ArmV8ABESysVDiv",
    "ArmV8ABESysVLDiv",
    "ArmV8ABESysVLLDiv",
    "ArmV8ABESysVExit",
    "ArmV8ABESysVFree",
    "ArmV8ABESysVMalloc",
    "ArmV8ABESysVQSort",
    "ArmV8ABESysVRand",
    "ArmV8ABESysVRealloc",
    "ArmV8ABESysVSrand",
    "ArmV8ABESysVAbort",
    "ArmV8ABESysVAtexit",
    "ArmV8ABESysVGetenv",
    "ArmV8ABESysVMblen",
    "ArmV8ABESysVMbstowcs",
    "ArmV8ABESysVMbtowc",
    "ArmV8ABESysVSystem",
    "ArmV8ABESysVWcstombs",
    "ArmV8ABESysVWctomb",
]
