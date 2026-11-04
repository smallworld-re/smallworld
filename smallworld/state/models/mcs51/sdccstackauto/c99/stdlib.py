from ....c99.stdlib import (
    Abs,
    Atof,
    Atoi,
    Atol,
    Atoll,
    Bsearch,
    Calloc,
    Free,
    LAbs,
    LLAbs,
    Malloc,
    QSort,
    Rand,
    Realloc,
    Srand,
)
from ....cstd import ArgumentType
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


class MCS51SDCCStackAutoBsearch(Bsearch, MCS51SDCCStackAutoModel):
    # The comparator is a function pointer: a code address, two bytes in the
    # small and large memory models, not a three-byte generic pointer.
    argument_types = [
        ArgumentType.POINTER,
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.SIZE_T,
        ArgumentType.UINT,
    ]


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


class MCS51SDCCStackAutoQSort(QSort, MCS51SDCCStackAutoModel):
    # The comparator is a code address, as for bsearch.
    argument_types = [
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.SIZE_T,
        ArgumentType.UINT,
    ]


class MCS51SDCCStackAutoRand(Rand, MCS51SDCCStackAutoModel):
    # SDCC's RAND_MAX; int is 16 bits.
    rand_max = 32767


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
    "MCS51SDCCStackAutoBsearch",
    "MCS51SDCCStackAutoCalloc",
    "MCS51SDCCStackAutoFree",
    "MCS51SDCCStackAutoLAbs",
    "MCS51SDCCStackAutoLLAbs",
    "MCS51SDCCStackAutoMalloc",
    "MCS51SDCCStackAutoQSort",
    "MCS51SDCCStackAutoRand",
    "MCS51SDCCStackAutoRealloc",
    "MCS51SDCCStackAutoSrand",
]
