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
from ..systemv import ArmHFSysVModel


class ArmHFSysVAbs(Abs, ArmHFSysVModel):
    pass


class ArmHFSysVLAbs(LAbs, ArmHFSysVModel):
    pass


class ArmHFSysVLLAbs(LLAbs, ArmHFSysVModel):
    pass


class ArmHFSysVAtof(Atof, ArmHFSysVModel):
    pass


class ArmHFSysVAtoi(Atoi, ArmHFSysVModel):
    pass


class ArmHFSysVAtol(Atol, ArmHFSysVModel):
    pass


class ArmHFSysVAtoll(Atoll, ArmHFSysVModel):
    pass


class ArmHFSysVCalloc(Calloc, ArmHFSysVModel):
    pass


class ArmHFSysVDiv(Div, ArmHFSysVModel):
    pass


class ArmHFSysVLDiv(LDiv, ArmHFSysVModel):
    pass


class ArmHFSysVLLDiv(LLDiv, ArmHFSysVModel):
    pass


class ArmHFSysVExit(Exit, ArmHFSysVModel):
    pass


class ArmHFSysVFree(Free, ArmHFSysVModel):
    pass


class ArmHFSysVMalloc(Malloc, ArmHFSysVModel):
    pass


class ArmHFSysVQSort(QSort, ArmHFSysVModel):
    pass


class ArmHFSysVRand(Rand, ArmHFSysVModel):
    pass


class ArmHFSysVRealloc(Realloc, ArmHFSysVModel):
    pass


class ArmHFSysVSrand(Srand, ArmHFSysVModel):
    pass


class ArmHFSysVAbort(Abort, ArmHFSysVModel):
    pass


class ArmHFSysVAtexit(Atexit, ArmHFSysVModel):
    pass


class ArmHFSysVGetenv(Getenv, ArmHFSysVModel):
    pass


class ArmHFSysVMblen(Mblen, ArmHFSysVModel):
    pass


class ArmHFSysVMbstowcs(Mbstowcs, ArmHFSysVModel):
    pass


class ArmHFSysVMbtowc(Mbtowc, ArmHFSysVModel):
    pass


class ArmHFSysVSystem(System, ArmHFSysVModel):
    pass


class ArmHFSysVWcstombs(Wcstombs, ArmHFSysVModel):
    pass


class ArmHFSysVWctomb(Wctomb, ArmHFSysVModel):
    pass


__all__ = [
    "ArmHFSysVAbs",
    "ArmHFSysVLAbs",
    "ArmHFSysVLLAbs",
    "ArmHFSysVAtof",
    "ArmHFSysVAtoi",
    "ArmHFSysVAtol",
    "ArmHFSysVAtoll",
    "ArmHFSysVCalloc",
    "ArmHFSysVDiv",
    "ArmHFSysVLDiv",
    "ArmHFSysVLLDiv",
    "ArmHFSysVExit",
    "ArmHFSysVFree",
    "ArmHFSysVMalloc",
    "ArmHFSysVQSort",
    "ArmHFSysVRand",
    "ArmHFSysVRealloc",
    "ArmHFSysVSrand",
    "ArmHFSysVAbort",
    "ArmHFSysVAtexit",
    "ArmHFSysVGetenv",
    "ArmHFSysVMblen",
    "ArmHFSysVMbstowcs",
    "ArmHFSysVMbtowc",
    "ArmHFSysVSystem",
    "ArmHFSysVWcstombs",
    "ArmHFSysVWctomb",
]
