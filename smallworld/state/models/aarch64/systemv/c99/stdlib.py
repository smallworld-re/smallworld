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
from ..systemv import AArch64SysVModel


class AArch64SysVAbs(Abs, AArch64SysVModel):
    pass


class AArch64SysVLAbs(LAbs, AArch64SysVModel):
    pass


class AArch64SysVLLAbs(LLAbs, AArch64SysVModel):
    pass


class AArch64SysVAtof(Atof, AArch64SysVModel):
    pass


class AArch64SysVAtoi(Atoi, AArch64SysVModel):
    pass


class AArch64SysVAtol(Atol, AArch64SysVModel):
    pass


class AArch64SysVAtoll(Atoll, AArch64SysVModel):
    pass


class AArch64SysVCalloc(Calloc, AArch64SysVModel):
    pass


class AArch64SysVDiv(Div, AArch64SysVModel):
    pass


class AArch64SysVLDiv(LDiv, AArch64SysVModel):
    pass


class AArch64SysVLLDiv(LLDiv, AArch64SysVModel):
    pass


class AArch64SysVExit(Exit, AArch64SysVModel):
    pass


class AArch64SysVFree(Free, AArch64SysVModel):
    pass


class AArch64SysVMalloc(Malloc, AArch64SysVModel):
    pass


class AArch64SysVQSort(QSort, AArch64SysVModel):
    pass


class AArch64SysVRand(Rand, AArch64SysVModel):
    pass


class AArch64SysVRealloc(Realloc, AArch64SysVModel):
    pass


class AArch64SysVSrand(Srand, AArch64SysVModel):
    pass


class AArch64SysVAbort(Abort, AArch64SysVModel):
    pass


class AArch64SysVAtexit(Atexit, AArch64SysVModel):
    pass


class AArch64SysVGetenv(Getenv, AArch64SysVModel):
    pass


class AArch64SysVMblen(Mblen, AArch64SysVModel):
    pass


class AArch64SysVMbstowcs(Mbstowcs, AArch64SysVModel):
    pass


class AArch64SysVMbtowc(Mbtowc, AArch64SysVModel):
    pass


class AArch64SysVSystem(System, AArch64SysVModel):
    pass


class AArch64SysVWcstombs(Wcstombs, AArch64SysVModel):
    pass


class AArch64SysVWctomb(Wctomb, AArch64SysVModel):
    pass


__all__ = [
    "AArch64SysVAbs",
    "AArch64SysVLAbs",
    "AArch64SysVLLAbs",
    "AArch64SysVAtof",
    "AArch64SysVAtoi",
    "AArch64SysVAtol",
    "AArch64SysVAtoll",
    "AArch64SysVCalloc",
    "AArch64SysVDiv",
    "AArch64SysVLDiv",
    "AArch64SysVLLDiv",
    "AArch64SysVExit",
    "AArch64SysVFree",
    "AArch64SysVMalloc",
    "AArch64SysVQSort",
    "AArch64SysVRand",
    "AArch64SysVRealloc",
    "AArch64SysVSrand",
    "AArch64SysVAbort",
    "AArch64SysVAtexit",
    "AArch64SysVGetenv",
    "AArch64SysVMblen",
    "AArch64SysVMbstowcs",
    "AArch64SysVMbtowc",
    "AArch64SysVSystem",
    "AArch64SysVWcstombs",
    "AArch64SysVWctomb",
]
