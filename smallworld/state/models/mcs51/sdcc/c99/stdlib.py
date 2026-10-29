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
from ..sdcc import MCS51SDCCModel


class MCS51SDCCAbs(Abs, MCS51SDCCModel):
    pass


class MCS51SDCCAtof(Atof, MCS51SDCCModel):
    pass


class MCS51SDCCAtoi(Atoi, MCS51SDCCModel):
    pass


class MCS51SDCCAtol(Atol, MCS51SDCCModel):
    pass


class MCS51SDCCAtoll(Atoll, MCS51SDCCModel):
    pass


class MCS51SDCCCalloc(Calloc, MCS51SDCCModel):
    pass


class MCS51SDCCFree(Free, MCS51SDCCModel):
    pass


class MCS51SDCCLAbs(LAbs, MCS51SDCCModel):
    pass


class MCS51SDCCLLAbs(LLAbs, MCS51SDCCModel):
    pass


class MCS51SDCCMalloc(Malloc, MCS51SDCCModel):
    pass


class MCS51SDCCRand(Rand, MCS51SDCCModel):
    pass


class MCS51SDCCRealloc(Realloc, MCS51SDCCModel):
    pass


class MCS51SDCCSrand(Srand, MCS51SDCCModel):
    pass


__all__ = [
    "MCS51SDCCAbs",
    "MCS51SDCCAtof",
    "MCS51SDCCAtoi",
    "MCS51SDCCAtol",
    "MCS51SDCCAtoll",
    "MCS51SDCCCalloc",
    "MCS51SDCCFree",
    "MCS51SDCCLAbs",
    "MCS51SDCCLLAbs",
    "MCS51SDCCMalloc",
    "MCS51SDCCRand",
    "MCS51SDCCRealloc",
    "MCS51SDCCSrand",
]
