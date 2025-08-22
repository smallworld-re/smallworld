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
from ..systemv import ArmHFSysVModel


class ArmHFSysVTime(Time, ArmHFSysVModel):
    pass


class ArmHFSysVLocaltime(Localtime, ArmHFSysVModel):
    pass


class ArmHFSysVGmtime(Gmtime, ArmHFSysVModel):
    pass


class ArmHFSysVCtime(Ctime, ArmHFSysVModel):
    pass


class ArmHFSysVAsctime(Asctime, ArmHFSysVModel):
    pass


class ArmHFSysVStrftime(Strftime, ArmHFSysVModel):
    pass


class ArmHFSysVDifftime(Difftime, ArmHFSysVModel):
    pass


class ArmHFSysVMktime(Mktime, ArmHFSysVModel):
    pass


class ArmHFSysVClock(Clock, ArmHFSysVModel):
    pass


__all__ = [
    "ArmHFSysVTime",
    "ArmHFSysVLocaltime",
    "ArmHFSysVGmtime",
    "ArmHFSysVCtime",
    "ArmHFSysVAsctime",
    "ArmHFSysVStrftime",
    "ArmHFSysVDifftime",
    "ArmHFSysVMktime",
    "ArmHFSysVClock",
]
