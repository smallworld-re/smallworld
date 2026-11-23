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
from ..systemv import ArmV8RSysVModel


class ArmV8RSysVAbs(Abs, ArmV8RSysVModel):
    pass


class ArmV8RSysVLAbs(LAbs, ArmV8RSysVModel):
    pass


class ArmV8RSysVLLAbs(LLAbs, ArmV8RSysVModel):
    pass


class ArmV8RSysVAtof(Atof, ArmV8RSysVModel):
    pass


class ArmV8RSysVAtoi(Atoi, ArmV8RSysVModel):
    pass


class ArmV8RSysVAtol(Atol, ArmV8RSysVModel):
    pass


class ArmV8RSysVAtoll(Atoll, ArmV8RSysVModel):
    pass


class ArmV8RSysVBsearch(Bsearch, ArmV8RSysVModel):
    pass


class ArmV8RSysVCalloc(Calloc, ArmV8RSysVModel):
    pass


class ArmV8RSysVDiv(Div, ArmV8RSysVModel):
    pass


class ArmV8RSysVLDiv(LDiv, ArmV8RSysVModel):
    pass


class ArmV8RSysVLLDiv(LLDiv, ArmV8RSysVModel):
    pass


class ArmV8RSysVExit(Exit, ArmV8RSysVModel):
    pass


class ArmV8RSysVFree(Free, ArmV8RSysVModel):
    pass


class ArmV8RSysVMalloc(Malloc, ArmV8RSysVModel):
    pass


class ArmV8RSysVQSort(QSort, ArmV8RSysVModel):
    pass


class ArmV8RSysVRand(Rand, ArmV8RSysVModel):
    pass


class ArmV8RSysVRealloc(Realloc, ArmV8RSysVModel):
    pass


class ArmV8RSysVSrand(Srand, ArmV8RSysVModel):
    pass


class ArmV8RSysVAbort(Abort, ArmV8RSysVModel):
    pass


class ArmV8RSysVAtexit(Atexit, ArmV8RSysVModel):
    pass


class ArmV8RSysVGetenv(Getenv, ArmV8RSysVModel):
    pass


class ArmV8RSysVMblen(Mblen, ArmV8RSysVModel):
    pass


class ArmV8RSysVMbstowcs(Mbstowcs, ArmV8RSysVModel):
    pass


class ArmV8RSysVMbtowc(Mbtowc, ArmV8RSysVModel):
    pass


class ArmV8RSysVSystem(System, ArmV8RSysVModel):
    pass


class ArmV8RSysVWcstombs(Wcstombs, ArmV8RSysVModel):
    pass


class ArmV8RSysVWctomb(Wctomb, ArmV8RSysVModel):
    pass


__all__ = [
    "ArmV8RSysVAbs",
    "ArmV8RSysVLAbs",
    "ArmV8RSysVLLAbs",
    "ArmV8RSysVAtof",
    "ArmV8RSysVAtoi",
    "ArmV8RSysVAtol",
    "ArmV8RSysVAtoll",
    "ArmV8RSysVBsearch",
    "ArmV8RSysVCalloc",
    "ArmV8RSysVDiv",
    "ArmV8RSysVLDiv",
    "ArmV8RSysVLLDiv",
    "ArmV8RSysVExit",
    "ArmV8RSysVFree",
    "ArmV8RSysVMalloc",
    "ArmV8RSysVQSort",
    "ArmV8RSysVRand",
    "ArmV8RSysVRealloc",
    "ArmV8RSysVSrand",
    "ArmV8RSysVAbort",
    "ArmV8RSysVAtexit",
    "ArmV8RSysVGetenv",
    "ArmV8RSysVMblen",
    "ArmV8RSysVMbstowcs",
    "ArmV8RSysVMbtowc",
    "ArmV8RSysVSystem",
    "ArmV8RSysVWcstombs",
    "ArmV8RSysVWctomb",
]
