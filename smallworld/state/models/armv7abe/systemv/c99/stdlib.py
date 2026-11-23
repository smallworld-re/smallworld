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
from ..systemv import ArmV7ABESysVModel


class ArmV7ABESysVAbs(Abs, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVLAbs(LAbs, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVLLAbs(LLAbs, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVAtof(Atof, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVAtoi(Atoi, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVAtol(Atol, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVAtoll(Atoll, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVBsearch(Bsearch, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVCalloc(Calloc, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVDiv(Div, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVLDiv(LDiv, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVLLDiv(LLDiv, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVExit(Exit, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVFree(Free, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVMalloc(Malloc, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVQSort(QSort, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVRand(Rand, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVRealloc(Realloc, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSrand(Srand, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVAbort(Abort, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVAtexit(Atexit, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVGetenv(Getenv, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVMblen(Mblen, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVMbstowcs(Mbstowcs, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVMbtowc(Mbtowc, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSystem(System, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVWcstombs(Wcstombs, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVWctomb(Wctomb, ArmV7ABESysVModel):
    pass


__all__ = [
    "ArmV7ABESysVAbs",
    "ArmV7ABESysVLAbs",
    "ArmV7ABESysVLLAbs",
    "ArmV7ABESysVAtof",
    "ArmV7ABESysVAtoi",
    "ArmV7ABESysVAtol",
    "ArmV7ABESysVAtoll",
    "ArmV7ABESysVBsearch",
    "ArmV7ABESysVCalloc",
    "ArmV7ABESysVDiv",
    "ArmV7ABESysVLDiv",
    "ArmV7ABESysVLLDiv",
    "ArmV7ABESysVExit",
    "ArmV7ABESysVFree",
    "ArmV7ABESysVMalloc",
    "ArmV7ABESysVQSort",
    "ArmV7ABESysVRand",
    "ArmV7ABESysVRealloc",
    "ArmV7ABESysVSrand",
    "ArmV7ABESysVAbort",
    "ArmV7ABESysVAtexit",
    "ArmV7ABESysVGetenv",
    "ArmV7ABESysVMblen",
    "ArmV7ABESysVMbstowcs",
    "ArmV7ABESysVMbtowc",
    "ArmV7ABESysVSystem",
    "ArmV7ABESysVWcstombs",
    "ArmV7ABESysVWctomb",
]
