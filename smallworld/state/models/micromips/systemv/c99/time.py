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
from ..systemv import MicroMIPSSysVModel


class MicroMIPSSysVTime(Time, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVLocaltime(Localtime, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVGmtime(Gmtime, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVCtime(Ctime, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVAsctime(Asctime, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVStrftime(Strftime, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVDifftime(Difftime, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVMktime(Mktime, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVClock(Clock, MicroMIPSSysVModel):
    pass


__all__ = [
    "MicroMIPSSysVTime",
    "MicroMIPSSysVLocaltime",
    "MicroMIPSSysVGmtime",
    "MicroMIPSSysVCtime",
    "MicroMIPSSysVAsctime",
    "MicroMIPSSysVStrftime",
    "MicroMIPSSysVDifftime",
    "MicroMIPSSysVMktime",
    "MicroMIPSSysVClock",
]
