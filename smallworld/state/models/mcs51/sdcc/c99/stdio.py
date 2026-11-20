from ....c99.stdio import (
    Getchar,
    Gets,
    Printf,
    Putchar,
    Puts,
    Sprintf,
)
from ..sdcc import MCS51SDCCModel


class MCS51SDCCGetchar(Getchar, MCS51SDCCModel):
    pass


class MCS51SDCCGets(Gets, MCS51SDCCModel):
    pass


class MCS51SDCCPrintf(Printf, MCS51SDCCModel):
    variadic = True


class MCS51SDCCPutchar(Putchar, MCS51SDCCModel):
    pass


class MCS51SDCCPuts(Puts, MCS51SDCCModel):
    pass


class MCS51SDCCSprintf(Sprintf, MCS51SDCCModel):
    variadic = True


__all__ = [
    "MCS51SDCCGetchar",
    "MCS51SDCCGets",
    "MCS51SDCCPrintf",
    "MCS51SDCCPutchar",
    "MCS51SDCCPuts",
    "MCS51SDCCSprintf",
]
