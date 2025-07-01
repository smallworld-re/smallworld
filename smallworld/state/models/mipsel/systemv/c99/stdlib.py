from ....c99 import (
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
from ..systemv import MIPSELSysVModel


class MIPSELSysVAbs(Abs, MIPSELSysVModel):
    pass


class MIPSELSysVLAbs(LAbs, MIPSELSysVModel):
    pass


class MIPSELSysVLLAbs(LLAbs, MIPSELSysVModel):
    pass


class MIPSELSysVAtof(Atof, MIPSELSysVModel):
    pass


class MIPSELSysVAtoi(Atoi, MIPSELSysVModel):
    pass


class MIPSELSysVAtol(Atol, MIPSELSysVModel):
    pass


class MIPSELSysVAtoll(Atoll, MIPSELSysVModel):
    pass


class MIPSELSysVCalloc(Calloc, MIPSELSysVModel):
    pass


class MIPSELSysVDiv(Div, MIPSELSysVModel):
    pass


class MIPSELSysVLDiv(LDiv, MIPSELSysVModel):
    pass


class MIPSELSysVLLDiv(LLDiv, MIPSELSysVModel):
    pass


class MIPSELSysVExit(Exit, MIPSELSysVModel):
    pass


class MIPSELSysVFree(Free, MIPSELSysVModel):
    pass


class MIPSELSysVMalloc(Malloc, MIPSELSysVModel):
    pass


class MIPSELSysVQSort(QSort, MIPSELSysVModel):
    pass


class MIPSELSysVRand(Rand, MIPSELSysVModel):
    pass


class MIPSELSysVRealloc(Realloc, MIPSELSysVModel):
    pass


class MIPSELSysVSrand(Srand, MIPSELSysVModel):
    pass


__all__ = [
    "MIPSELSysVAbs",
    "MIPSELSysVLAbs",
    "MIPSELSysVLLAbs",
    "MIPSELSysVAtof",
    "MIPSELSysVAtoi",
    "MIPSELSysVAtol",
    "MIPSELSysVAtoll",
    "MIPSELSysVCalloc",
    "MIPSELSysVDiv",
    "MIPSELSysVLDiv",
    "MIPSELSysVLLDiv",
    "MIPSELSysVExit",
    "MIPSELSysVFree",
    "MIPSELSysVMalloc",
    "MIPSELSysVQSort",
    "MIPSELSysVRand",
    "MIPSELSysVRealloc",
    "MIPSELSysVSrand",
]
