from ....c99 import (
    Abort,
    Abs,
    Atexit,
    Atof,
    Atoi,
    Atol,
    Atoll,
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
from ..systemv import ArmELSysVModel


class ArmELSysVAbs(Abs, ArmELSysVModel):
    pass


class ArmELSysVLAbs(LAbs, ArmELSysVModel):
    pass


class ArmELSysVLLAbs(LLAbs, ArmELSysVModel):
    pass


class ArmELSysVAtof(Atof, ArmELSysVModel):
    pass


class ArmELSysVAtoi(Atoi, ArmELSysVModel):
    pass


class ArmELSysVAtol(Atol, ArmELSysVModel):
    pass


class ArmELSysVAtoll(Atoll, ArmELSysVModel):
    pass


class ArmELSysVCalloc(Calloc, ArmELSysVModel):
    pass


class ArmELSysVDiv(Div, ArmELSysVModel):
    pass


class ArmELSysVLDiv(LDiv, ArmELSysVModel):
    pass


class ArmELSysVLLDiv(LLDiv, ArmELSysVModel):
    pass


class ArmELSysVExit(Exit, ArmELSysVModel):
    pass


class ArmELSysVFree(Free, ArmELSysVModel):
    pass


class ArmELSysVMalloc(Malloc, ArmELSysVModel):
    pass


class ArmELSysVQSort(QSort, ArmELSysVModel):
    pass


class ArmELSysVRand(Rand, ArmELSysVModel):
    pass


class ArmELSysVRealloc(Realloc, ArmELSysVModel):
    pass


class ArmELSysVSrand(Srand, ArmELSysVModel):
    pass


class ArmELSysVAbort(Abort, ArmELSysVModel):
    pass


class ArmELSysVAtexit(Atexit, ArmELSysVModel):
    pass


class ArmELSysVGetenv(Getenv, ArmELSysVModel):
    pass


class ArmELSysVMblen(Mblen, ArmELSysVModel):
    pass


class ArmELSysVMbstowcs(Mbstowcs, ArmELSysVModel):
    pass


class ArmELSysVMbtowc(Mbtowc, ArmELSysVModel):
    pass


class ArmELSysVSystem(System, ArmELSysVModel):
    pass


class ArmELSysVWcstombs(Wcstombs, ArmELSysVModel):
    pass


class ArmELSysVWctomb(Wctomb, ArmELSysVModel):
    pass


__all__ = [
    "ArmELSysVAbs",
    "ArmELSysVLAbs",
    "ArmELSysVLLAbs",
    "ArmELSysVAtof",
    "ArmELSysVAtoi",
    "ArmELSysVAtol",
    "ArmELSysVAtoll",
    "ArmELSysVCalloc",
    "ArmELSysVDiv",
    "ArmELSysVLDiv",
    "ArmELSysVLLDiv",
    "ArmELSysVExit",
    "ArmELSysVFree",
    "ArmELSysVMalloc",
    "ArmELSysVQSort",
    "ArmELSysVRand",
    "ArmELSysVRealloc",
    "ArmELSysVSrand",
    "ArmELSysVAbort",
    "ArmELSysVAtexit",
    "ArmELSysVGetenv",
    "ArmELSysVMblen",
    "ArmELSysVMbstowcs",
    "ArmELSysVMbtowc",
    "ArmELSysVSystem",
    "ArmELSysVWcstombs",
    "ArmELSysVWctomb",
]
