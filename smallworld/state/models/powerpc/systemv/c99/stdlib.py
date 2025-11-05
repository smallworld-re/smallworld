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
from ..systemv import PowerPCSysVModel


class PowerPCSysVAbs(Abs, PowerPCSysVModel):
    pass


class PowerPCSysVLAbs(LAbs, PowerPCSysVModel):
    pass


class PowerPCSysVLLAbs(LLAbs, PowerPCSysVModel):
    pass


class PowerPCSysVAtof(Atof, PowerPCSysVModel):
    pass


class PowerPCSysVAtoi(Atoi, PowerPCSysVModel):
    pass


class PowerPCSysVAtol(Atol, PowerPCSysVModel):
    pass


class PowerPCSysVAtoll(Atoll, PowerPCSysVModel):
    pass


class PowerPCSysVBsearch(Bsearch, PowerPCSysVModel):
    pass


class PowerPCSysVCalloc(Calloc, PowerPCSysVModel):
    pass


class PowerPCSysVDiv(Div, PowerPCSysVModel):
    pass


class PowerPCSysVLDiv(LDiv, PowerPCSysVModel):
    pass


class PowerPCSysVLLDiv(LLDiv, PowerPCSysVModel):
    pass


class PowerPCSysVExit(Exit, PowerPCSysVModel):
    pass


class PowerPCSysVFree(Free, PowerPCSysVModel):
    pass


class PowerPCSysVMalloc(Malloc, PowerPCSysVModel):
    pass


class PowerPCSysVQSort(QSort, PowerPCSysVModel):
    pass


class PowerPCSysVRand(Rand, PowerPCSysVModel):
    pass


class PowerPCSysVRealloc(Realloc, PowerPCSysVModel):
    pass


class PowerPCSysVSrand(Srand, PowerPCSysVModel):
    pass


class PowerPCSysVAbort(Abort, PowerPCSysVModel):
    pass


class PowerPCSysVAtexit(Atexit, PowerPCSysVModel):
    pass


class PowerPCSysVGetenv(Getenv, PowerPCSysVModel):
    pass


class PowerPCSysVMblen(Mblen, PowerPCSysVModel):
    pass


class PowerPCSysVMbstowcs(Mbstowcs, PowerPCSysVModel):
    pass


class PowerPCSysVMbtowc(Mbtowc, PowerPCSysVModel):
    pass


class PowerPCSysVSystem(System, PowerPCSysVModel):
    pass


class PowerPCSysVWcstombs(Wcstombs, PowerPCSysVModel):
    pass


class PowerPCSysVWctomb(Wctomb, PowerPCSysVModel):
    pass


__all__ = [
    "PowerPCSysVAbs",
    "PowerPCSysVLAbs",
    "PowerPCSysVLLAbs",
    "PowerPCSysVAtof",
    "PowerPCSysVAtoi",
    "PowerPCSysVAtol",
    "PowerPCSysVAtoll",
    "PowerPCSysVBsearch",
    "PowerPCSysVCalloc",
    "PowerPCSysVDiv",
    "PowerPCSysVLDiv",
    "PowerPCSysVLLDiv",
    "PowerPCSysVExit",
    "PowerPCSysVFree",
    "PowerPCSysVMalloc",
    "PowerPCSysVQSort",
    "PowerPCSysVRand",
    "PowerPCSysVRealloc",
    "PowerPCSysVSrand",
    "PowerPCSysVAbort",
    "PowerPCSysVAtexit",
    "PowerPCSysVGetenv",
    "PowerPCSysVMblen",
    "PowerPCSysVMbstowcs",
    "PowerPCSysVMbtowc",
    "PowerPCSysVSystem",
    "PowerPCSysVWcstombs",
    "PowerPCSysVWctomb",
]
