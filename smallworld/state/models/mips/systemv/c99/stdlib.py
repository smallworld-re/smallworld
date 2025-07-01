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
]
