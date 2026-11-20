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


class MCS51SDCCBsearch(Bsearch, MCS51SDCCModel):
    # The comparator is a function pointer: a code address, two bytes in the
    # small and large memory models, not a three-byte generic pointer.
    argument_types = [
        ArgumentType.POINTER,
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.SIZE_T,
        ArgumentType.UINT,
    ]


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


class MCS51SDCCQSort(QSort, MCS51SDCCModel):
    # The comparator is a code address, as for bsearch.
    argument_types = [
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.SIZE_T,
        ArgumentType.UINT,
    ]


class MCS51SDCCRand(Rand, MCS51SDCCModel):
    # SDCC's RAND_MAX; int is 16 bits.
    rand_max = 32767


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
    "MCS51SDCCBsearch",
    "MCS51SDCCCalloc",
    "MCS51SDCCFree",
    "MCS51SDCCLAbs",
    "MCS51SDCCLLAbs",
    "MCS51SDCCMalloc",
    "MCS51SDCCQSort",
    "MCS51SDCCRand",
    "MCS51SDCCRealloc",
    "MCS51SDCCSrand",
]
