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
]
