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
]
