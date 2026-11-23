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
from ..systemv import AArch64BESysVModel


class AArch64BESysVTime(Time, AArch64BESysVModel):
    pass


class AArch64BESysVLocaltime(Localtime, AArch64BESysVModel):
    pass


class AArch64BESysVGmtime(Gmtime, AArch64BESysVModel):
    pass


class AArch64BESysVCtime(Ctime, AArch64BESysVModel):
    pass


class AArch64BESysVAsctime(Asctime, AArch64BESysVModel):
    pass


class AArch64BESysVStrftime(Strftime, AArch64BESysVModel):
    pass


class AArch64BESysVDifftime(Difftime, AArch64BESysVModel):
    pass


class AArch64BESysVMktime(Mktime, AArch64BESysVModel):
    pass


class AArch64BESysVClock(Clock, AArch64BESysVModel):
    pass


__all__ = [
    "AArch64BESysVTime",
    "AArch64BESysVLocaltime",
    "AArch64BESysVGmtime",
    "AArch64BESysVCtime",
    "AArch64BESysVAsctime",
    "AArch64BESysVStrftime",
    "AArch64BESysVDifftime",
    "AArch64BESysVMktime",
    "AArch64BESysVClock",
]
