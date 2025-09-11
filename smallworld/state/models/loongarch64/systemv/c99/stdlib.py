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
from ..systemv import LoongArch64SysVModel


class LoongArch64SysVAbs(Abs, LoongArch64SysVModel):
    pass


class LoongArch64SysVLAbs(LAbs, LoongArch64SysVModel):
    pass


class LoongArch64SysVLLAbs(LLAbs, LoongArch64SysVModel):
    pass


class LoongArch64SysVAtof(Atof, LoongArch64SysVModel):
    pass


class LoongArch64SysVAtoi(Atoi, LoongArch64SysVModel):
    pass


class LoongArch64SysVAtol(Atol, LoongArch64SysVModel):
    pass


class LoongArch64SysVAtoll(Atoll, LoongArch64SysVModel):
    pass


class LoongArch64SysVCalloc(Calloc, LoongArch64SysVModel):
    pass


class LoongArch64SysVDiv(Div, LoongArch64SysVModel):
    pass


class LoongArch64SysVLDiv(LDiv, LoongArch64SysVModel):
    pass


class LoongArch64SysVLLDiv(LLDiv, LoongArch64SysVModel):
    pass


class LoongArch64SysVExit(Exit, LoongArch64SysVModel):
    pass


class LoongArch64SysVFree(Free, LoongArch64SysVModel):
    pass


class LoongArch64SysVMalloc(Malloc, LoongArch64SysVModel):
    pass


class LoongArch64SysVQSort(QSort, LoongArch64SysVModel):
    pass


class LoongArch64SysVRand(Rand, LoongArch64SysVModel):
    pass


class LoongArch64SysVRealloc(Realloc, LoongArch64SysVModel):
    pass


class LoongArch64SysVSrand(Srand, LoongArch64SysVModel):
    pass


class LoongArch64SysVAbort(Abort, LoongArch64SysVModel):
    pass


class LoongArch64SysVAtexit(Atexit, LoongArch64SysVModel):
    pass


class LoongArch64SysVGetenv(Getenv, LoongArch64SysVModel):
    pass


class LoongArch64SysVMblen(Mblen, LoongArch64SysVModel):
    pass


class LoongArch64SysVMbstowcs(Mbstowcs, LoongArch64SysVModel):
    pass


class LoongArch64SysVMbtowc(Mbtowc, LoongArch64SysVModel):
    pass


class LoongArch64SysVSystem(System, LoongArch64SysVModel):
    pass


class LoongArch64SysVWcstombs(Wcstombs, LoongArch64SysVModel):
    pass


class LoongArch64SysVWctomb(Wctomb, LoongArch64SysVModel):
    pass


__all__ = [
    "LoongArch64SysVAbs",
    "LoongArch64SysVLAbs",
    "LoongArch64SysVLLAbs",
    "LoongArch64SysVAtof",
    "LoongArch64SysVAtoi",
    "LoongArch64SysVAtol",
    "LoongArch64SysVAtoll",
    "LoongArch64SysVCalloc",
    "LoongArch64SysVDiv",
    "LoongArch64SysVLDiv",
    "LoongArch64SysVLLDiv",
    "LoongArch64SysVExit",
    "LoongArch64SysVFree",
    "LoongArch64SysVMalloc",
    "LoongArch64SysVQSort",
    "LoongArch64SysVRand",
    "LoongArch64SysVRealloc",
    "LoongArch64SysVSrand",
    "LoongArch64SysVAbort",
    "LoongArch64SysVAtexit",
    "LoongArch64SysVGetenv",
    "LoongArch64SysVMblen",
    "LoongArch64SysVMbstowcs",
    "LoongArch64SysVMbtowc",
    "LoongArch64SysVSystem",
    "LoongArch64SysVWcstombs",
    "LoongArch64SysVWctomb",
]
