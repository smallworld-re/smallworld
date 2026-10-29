from ....c99.stdio import (
    Getchar,
    Gets,
    Printf,
    Putchar,
    Puts,
    Sprintf,
)
from ..sdccstackauto import MCS51SDCCStackAutoModel


class MCS51SDCCStackAutoGetchar(Getchar, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoGets(Gets, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoPrintf(Printf, MCS51SDCCStackAutoModel):
    variadic = True


class MCS51SDCCStackAutoPutchar(Putchar, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoPuts(Puts, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoSprintf(Sprintf, MCS51SDCCStackAutoModel):
    variadic = True


__all__ = [
    "MCS51SDCCStackAutoGetchar",
    "MCS51SDCCStackAutoGets",
    "MCS51SDCCStackAutoPrintf",
    "MCS51SDCCStackAutoPutchar",
    "MCS51SDCCStackAutoPuts",
    "MCS51SDCCStackAutoSprintf",
]
