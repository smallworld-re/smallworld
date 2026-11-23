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
from ..systemv import AArch64V85ABESysVModel


class AArch64V85ABESysVTime(Time, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVLocaltime(Localtime, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVGmtime(Gmtime, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVCtime(Ctime, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVAsctime(Asctime, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVStrftime(Strftime, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVDifftime(Difftime, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVMktime(Mktime, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVClock(Clock, AArch64V85ABESysVModel):
    pass


__all__ = [
    "AArch64V85ABESysVTime",
    "AArch64V85ABESysVLocaltime",
    "AArch64V85ABESysVGmtime",
    "AArch64V85ABESysVCtime",
    "AArch64V85ABESysVAsctime",
    "AArch64V85ABESysVStrftime",
    "AArch64V85ABESysVDifftime",
    "AArch64V85ABESysVMktime",
    "AArch64V85ABESysVClock",
]
