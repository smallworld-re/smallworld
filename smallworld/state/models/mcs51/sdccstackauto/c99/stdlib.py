from ....c99.stdlib import (
    Abs,
    Atof,
    Atoi,
    Atol,
    Atoll,
    Calloc,
    Free,
    LAbs,
    LLAbs,
    Malloc,
    Rand,
    Realloc,
    Srand,
)
from ..sdccstackauto import MCS51SDCCStackAutoModel


class MCS51SDCCStackAutoAbs(Abs, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoAtof(Atof, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoAtoi(Atoi, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoAtol(Atol, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoAtoll(Atoll, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoCalloc(Calloc, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoFree(Free, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoLAbs(LAbs, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoLLAbs(LLAbs, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoMalloc(Malloc, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoRand(Rand, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoRealloc(Realloc, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoSrand(Srand, MCS51SDCCStackAutoModel):
    pass


__all__ = [
    "MCS51SDCCStackAutoAbs",
    "MCS51SDCCStackAutoAtof",
    "MCS51SDCCStackAutoAtoi",
    "MCS51SDCCStackAutoAtol",
    "MCS51SDCCStackAutoAtoll",
    "MCS51SDCCStackAutoCalloc",
    "MCS51SDCCStackAutoFree",
    "MCS51SDCCStackAutoLAbs",
    "MCS51SDCCStackAutoLLAbs",
    "MCS51SDCCStackAutoMalloc",
    "MCS51SDCCStackAutoRand",
    "MCS51SDCCStackAutoRealloc",
    "MCS51SDCCStackAutoSrand",
]
