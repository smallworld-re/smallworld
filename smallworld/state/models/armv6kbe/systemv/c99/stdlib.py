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
from ..systemv import ArmV6KBESysVModel


class ArmV6KBESysVAbs(Abs, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVLAbs(LAbs, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVLLAbs(LLAbs, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVAtof(Atof, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVAtoi(Atoi, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVAtol(Atol, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVAtoll(Atoll, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVBsearch(Bsearch, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVCalloc(Calloc, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVDiv(Div, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVLDiv(LDiv, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVLLDiv(LLDiv, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVExit(Exit, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVFree(Free, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVMalloc(Malloc, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVQSort(QSort, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVRand(Rand, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVRealloc(Realloc, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSrand(Srand, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVAbort(Abort, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVAtexit(Atexit, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVGetenv(Getenv, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVMblen(Mblen, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVMbstowcs(Mbstowcs, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVMbtowc(Mbtowc, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSystem(System, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVWcstombs(Wcstombs, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVWctomb(Wctomb, ArmV6KBESysVModel):
    pass


__all__ = [
    "ArmV6KBESysVAbs",
    "ArmV6KBESysVLAbs",
    "ArmV6KBESysVLLAbs",
    "ArmV6KBESysVAtof",
    "ArmV6KBESysVAtoi",
    "ArmV6KBESysVAtol",
    "ArmV6KBESysVAtoll",
    "ArmV6KBESysVBsearch",
    "ArmV6KBESysVCalloc",
    "ArmV6KBESysVDiv",
    "ArmV6KBESysVLDiv",
    "ArmV6KBESysVLLDiv",
    "ArmV6KBESysVExit",
    "ArmV6KBESysVFree",
    "ArmV6KBESysVMalloc",
    "ArmV6KBESysVQSort",
    "ArmV6KBESysVRand",
    "ArmV6KBESysVRealloc",
    "ArmV6KBESysVSrand",
    "ArmV6KBESysVAbort",
    "ArmV6KBESysVAtexit",
    "ArmV6KBESysVGetenv",
    "ArmV6KBESysVMblen",
    "ArmV6KBESysVMbstowcs",
    "ArmV6KBESysVMbtowc",
    "ArmV6KBESysVSystem",
    "ArmV6KBESysVWcstombs",
    "ArmV6KBESysVWctomb",
]
