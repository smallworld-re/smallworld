from ....c99 import (
    Asctime,
    Clock,
    Ctime,
    Difftime,
    Gmtime,
    Localtime,
    Mktime,
    Strftime,
    Time,
)
from ..systemv import MIPSSysVModel


class MIPSSysVTime(Time, MIPSSysVModel):
    pass


class MIPSSysVLocaltime(Localtime, MIPSSysVModel):
    pass


class MIPSSysVGmtime(Gmtime, MIPSSysVModel):
    pass


class MIPSSysVCtime(Ctime, MIPSSysVModel):
    pass


class MIPSSysVAsctime(Asctime, MIPSSysVModel):
    pass


class MIPSSysVStrftime(Strftime, MIPSSysVModel):
    pass


class MIPSSysVDifftime(Difftime, MIPSSysVModel):
    pass


class MIPSSysVMktime(Mktime, MIPSSysVModel):
    pass


class MIPSSysVClock(Clock, MIPSSysVModel):
    pass


__all__ = [
    "MIPSSysVTime",
    "MIPSSysVLocaltime",
    "MIPSSysVGmtime",
    "MIPSSysVCtime",
    "MIPSSysVAsctime",
    "MIPSSysVStrftime",
    "MIPSSysVDifftime",
    "MIPSSysVMktime",
    "MIPSSysVClock",
]
