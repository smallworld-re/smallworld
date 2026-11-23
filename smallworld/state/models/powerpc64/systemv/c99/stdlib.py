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
from ..systemv import PowerPC64SysVModel


class PowerPC64SysVAbs(Abs, PowerPC64SysVModel):
    pass


class PowerPC64SysVLAbs(LAbs, PowerPC64SysVModel):
    pass


class PowerPC64SysVLLAbs(LLAbs, PowerPC64SysVModel):
    pass


class PowerPC64SysVAtof(Atof, PowerPC64SysVModel):
    pass


class PowerPC64SysVAtoi(Atoi, PowerPC64SysVModel):
    pass


class PowerPC64SysVAtol(Atol, PowerPC64SysVModel):
    pass


class PowerPC64SysVAtoll(Atoll, PowerPC64SysVModel):
    pass


class PowerPC64SysVBsearch(Bsearch, PowerPC64SysVModel):
    pass


class PowerPC64SysVCalloc(Calloc, PowerPC64SysVModel):
    pass


class PowerPC64SysVDiv(Div, PowerPC64SysVModel):
    pass


class PowerPC64SysVLDiv(LDiv, PowerPC64SysVModel):
    pass


class PowerPC64SysVLLDiv(LLDiv, PowerPC64SysVModel):
    pass


class PowerPC64SysVExit(Exit, PowerPC64SysVModel):
    pass


class PowerPC64SysVFree(Free, PowerPC64SysVModel):
    pass


class PowerPC64SysVMalloc(Malloc, PowerPC64SysVModel):
    pass


class PowerPC64SysVQSort(QSort, PowerPC64SysVModel):
    pass


class PowerPC64SysVRand(Rand, PowerPC64SysVModel):
    pass


class PowerPC64SysVRealloc(Realloc, PowerPC64SysVModel):
    pass


class PowerPC64SysVSrand(Srand, PowerPC64SysVModel):
    pass


class PowerPC64SysVAbort(Abort, PowerPC64SysVModel):
    pass


class PowerPC64SysVAtexit(Atexit, PowerPC64SysVModel):
    pass


class PowerPC64SysVGetenv(Getenv, PowerPC64SysVModel):
    pass


class PowerPC64SysVMblen(Mblen, PowerPC64SysVModel):
    pass


class PowerPC64SysVMbstowcs(Mbstowcs, PowerPC64SysVModel):
    pass


class PowerPC64SysVMbtowc(Mbtowc, PowerPC64SysVModel):
    pass


class PowerPC64SysVSystem(System, PowerPC64SysVModel):
    pass


class PowerPC64SysVWcstombs(Wcstombs, PowerPC64SysVModel):
    pass


class PowerPC64SysVWctomb(Wctomb, PowerPC64SysVModel):
    pass


__all__ = [
    "PowerPC64SysVAbs",
    "PowerPC64SysVLAbs",
    "PowerPC64SysVLLAbs",
    "PowerPC64SysVAtof",
    "PowerPC64SysVAtoi",
    "PowerPC64SysVAtol",
    "PowerPC64SysVAtoll",
    "PowerPC64SysVBsearch",
    "PowerPC64SysVCalloc",
    "PowerPC64SysVDiv",
    "PowerPC64SysVLDiv",
    "PowerPC64SysVLLDiv",
    "PowerPC64SysVExit",
    "PowerPC64SysVFree",
    "PowerPC64SysVMalloc",
    "PowerPC64SysVQSort",
    "PowerPC64SysVRand",
    "PowerPC64SysVRealloc",
    "PowerPC64SysVSrand",
    "PowerPC64SysVAbort",
    "PowerPC64SysVAtexit",
    "PowerPC64SysVGetenv",
    "PowerPC64SysVMblen",
    "PowerPC64SysVMbstowcs",
    "PowerPC64SysVMbtowc",
    "PowerPC64SysVSystem",
    "PowerPC64SysVWcstombs",
    "PowerPC64SysVWctomb",
]
