from ...c99 import (
    Abs,
    Atof,
    Atoi,
    Atol,
    Atoll,
    Calloc,
    Div,
    Exit,
    Free,
    LAbs,
    LDiv,
    LLAbs,
    LLDiv,
    Malloc,
    QSort,
    Rand,
    Realloc,
    Srand,
)
from ..systemv import MIPS64ELSysVModel


class MIPS64ELSysVAbs(Abs, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVLAbs(LAbs, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVLLAbs(LLAbs, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVAtof(Atof, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVAtoi(Atoi, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVAtol(Atol, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVAtoll(Atoll, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVCalloc(Calloc, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVDiv(Div, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVLDiv(LDiv, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVLLDiv(LLDiv, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVExit(Exit, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVFree(Free, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVMalloc(Malloc, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVQSort(QSort, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVRand(Rand, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVRealloc(Realloc, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSrand(Srand, MIPS64ELSysVModel):
    pass


__all__ = [
    "MIPS64ELSysVAbs",
    "MIPS64ELSysVLAbs",
    "MIPS64ELSysVLLAbs",
    "MIPS64ELSysVAtof",
    "MIPS64ELSysVAtoi",
    "MIPS64ELSysVAtol",
    "MIPS64ELSysVAtoll",
    "MIPS64ELSysVCalloc",
    "MIPS64ELSysVDiv",
    "MIPS64ELSysVLDiv",
    "MIPS64ELSysVLLDiv",
    "MIPS64ELSysVExit",
    "MIPS64ELSysVFree",
    "MIPS64ELSysVMalloc",
    "MIPS64ELSysVQSort",
    "MIPS64ELSysVRand",
    "MIPS64ELSysVRealloc",
    "MIPS64ELSysVSrand",
]
