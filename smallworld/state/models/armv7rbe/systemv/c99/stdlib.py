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
from ..systemv import ArmV7RBESysVModel


class ArmV7RBESysVAbs(Abs, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVLAbs(LAbs, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVLLAbs(LLAbs, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVAtof(Atof, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVAtoi(Atoi, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVAtol(Atol, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVAtoll(Atoll, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVBsearch(Bsearch, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVCalloc(Calloc, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVDiv(Div, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVLDiv(LDiv, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVLLDiv(LLDiv, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVExit(Exit, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVFree(Free, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVMalloc(Malloc, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVQSort(QSort, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVRand(Rand, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVRealloc(Realloc, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSrand(Srand, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVAbort(Abort, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVAtexit(Atexit, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVGetenv(Getenv, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVMblen(Mblen, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVMbstowcs(Mbstowcs, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVMbtowc(Mbtowc, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSystem(System, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVWcstombs(Wcstombs, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVWctomb(Wctomb, ArmV7RBESysVModel):
    pass


__all__ = [
    "ArmV7RBESysVAbs",
    "ArmV7RBESysVLAbs",
    "ArmV7RBESysVLLAbs",
    "ArmV7RBESysVAtof",
    "ArmV7RBESysVAtoi",
    "ArmV7RBESysVAtol",
    "ArmV7RBESysVAtoll",
    "ArmV7RBESysVBsearch",
    "ArmV7RBESysVCalloc",
    "ArmV7RBESysVDiv",
    "ArmV7RBESysVLDiv",
    "ArmV7RBESysVLLDiv",
    "ArmV7RBESysVExit",
    "ArmV7RBESysVFree",
    "ArmV7RBESysVMalloc",
    "ArmV7RBESysVQSort",
    "ArmV7RBESysVRand",
    "ArmV7RBESysVRealloc",
    "ArmV7RBESysVSrand",
    "ArmV7RBESysVAbort",
    "ArmV7RBESysVAtexit",
    "ArmV7RBESysVGetenv",
    "ArmV7RBESysVMblen",
    "ArmV7RBESysVMbstowcs",
    "ArmV7RBESysVMbtowc",
    "ArmV7RBESysVSystem",
    "ArmV7RBESysVWcstombs",
    "ArmV7RBESysVWctomb",
]
