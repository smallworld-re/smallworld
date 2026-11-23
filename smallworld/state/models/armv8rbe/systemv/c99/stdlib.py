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
from ..systemv import ArmV8RBESysVModel


class ArmV8RBESysVAbs(Abs, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVLAbs(LAbs, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVLLAbs(LLAbs, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVAtof(Atof, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVAtoi(Atoi, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVAtol(Atol, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVAtoll(Atoll, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVBsearch(Bsearch, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVCalloc(Calloc, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVDiv(Div, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVLDiv(LDiv, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVLLDiv(LLDiv, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVExit(Exit, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVFree(Free, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVMalloc(Malloc, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVQSort(QSort, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVRand(Rand, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVRealloc(Realloc, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSrand(Srand, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVAbort(Abort, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVAtexit(Atexit, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVGetenv(Getenv, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVMblen(Mblen, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVMbstowcs(Mbstowcs, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVMbtowc(Mbtowc, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSystem(System, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVWcstombs(Wcstombs, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVWctomb(Wctomb, ArmV8RBESysVModel):
    pass


__all__ = [
    "ArmV8RBESysVAbs",
    "ArmV8RBESysVLAbs",
    "ArmV8RBESysVLLAbs",
    "ArmV8RBESysVAtof",
    "ArmV8RBESysVAtoi",
    "ArmV8RBESysVAtol",
    "ArmV8RBESysVAtoll",
    "ArmV8RBESysVBsearch",
    "ArmV8RBESysVCalloc",
    "ArmV8RBESysVDiv",
    "ArmV8RBESysVLDiv",
    "ArmV8RBESysVLLDiv",
    "ArmV8RBESysVExit",
    "ArmV8RBESysVFree",
    "ArmV8RBESysVMalloc",
    "ArmV8RBESysVQSort",
    "ArmV8RBESysVRand",
    "ArmV8RBESysVRealloc",
    "ArmV8RBESysVSrand",
    "ArmV8RBESysVAbort",
    "ArmV8RBESysVAtexit",
    "ArmV8RBESysVGetenv",
    "ArmV8RBESysVMblen",
    "ArmV8RBESysVMbstowcs",
    "ArmV8RBESysVMbtowc",
    "ArmV8RBESysVSystem",
    "ArmV8RBESysVWcstombs",
    "ArmV8RBESysVWctomb",
]
