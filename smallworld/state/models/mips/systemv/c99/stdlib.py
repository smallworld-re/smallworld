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
from ..systemv import MIPSSysVModel


class MIPSSysVAbs(Abs, MIPSSysVModel):
    pass


class MIPSSysVLAbs(LAbs, MIPSSysVModel):
    pass


class MIPSSysVLLAbs(LLAbs, MIPSSysVModel):
    pass


class MIPSSysVAtof(Atof, MIPSSysVModel):
    pass


class MIPSSysVAtoi(Atoi, MIPSSysVModel):
    pass


class MIPSSysVAtol(Atol, MIPSSysVModel):
    pass


class MIPSSysVAtoll(Atoll, MIPSSysVModel):
    pass


class MIPSSysVCalloc(Calloc, MIPSSysVModel):
    pass


class MIPSSysVDiv(Div, MIPSSysVModel):
    pass


class MIPSSysVLDiv(LDiv, MIPSSysVModel):
    pass


class MIPSSysVLLDiv(LLDiv, MIPSSysVModel):
    pass


class MIPSSysVExit(Exit, MIPSSysVModel):
    pass


class MIPSSysVFree(Free, MIPSSysVModel):
    pass


class MIPSSysVMalloc(Malloc, MIPSSysVModel):
    pass


class MIPSSysVQSort(QSort, MIPSSysVModel):
    pass


class MIPSSysVRand(Rand, MIPSSysVModel):
    pass


class MIPSSysVRealloc(Realloc, MIPSSysVModel):
    pass


class MIPSSysVSrand(Srand, MIPSSysVModel):
    pass


class MIPSSysVAbort(Abort, MIPSSysVModel):
    pass


class MIPSSysVAtexit(Atexit, MIPSSysVModel):
    pass


class MIPSSysVGetenv(Getenv, MIPSSysVModel):
    pass


class MIPSSysVMblen(Mblen, MIPSSysVModel):
    pass


class MIPSSysVMbstowcs(Mbstowcs, MIPSSysVModel):
    pass


class MIPSSysVMbtowc(Mbtowc, MIPSSysVModel):
    pass


class MIPSSysVSystem(System, MIPSSysVModel):
    pass


class MIPSSysVWcstombs(Wcstombs, MIPSSysVModel):
    pass


class MIPSSysVWctomb(Wctomb, MIPSSysVModel):
    pass


__all__ = [
    "MIPSSysVAbs",
    "MIPSSysVLAbs",
    "MIPSSysVLLAbs",
    "MIPSSysVAtof",
    "MIPSSysVAtoi",
    "MIPSSysVAtol",
    "MIPSSysVAtoll",
    "MIPSSysVCalloc",
    "MIPSSysVDiv",
    "MIPSSysVLDiv",
    "MIPSSysVLLDiv",
    "MIPSSysVExit",
    "MIPSSysVFree",
    "MIPSSysVMalloc",
    "MIPSSysVQSort",
    "MIPSSysVRand",
    "MIPSSysVRealloc",
    "MIPSSysVSrand",
    "MIPSSysVAbort",
    "MIPSSysVAtexit",
    "MIPSSysVGetenv",
    "MIPSSysVMblen",
    "MIPSSysVMbstowcs",
    "MIPSSysVMbtowc",
    "MIPSSysVSystem",
    "MIPSSysVWcstombs",
    "MIPSSysVWctomb",
]
