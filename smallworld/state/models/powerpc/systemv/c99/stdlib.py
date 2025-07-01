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


__all__ = [
    "PowerPCSysVAbs",
    "PowerPCSysVLAbs",
    "PowerPCSysVLLAbs",
    "PowerPCSysVAtof",
    "PowerPCSysVAtoi",
    "PowerPCSysVAtol",
    "PowerPCSysVAtoll",
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
]
