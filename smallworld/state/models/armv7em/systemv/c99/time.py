from ....c99 import (
    Asctime,
    Clock,
    Ctime,
    Ctime64,
    Difftime,
    Difftime64,
    Gmtime,
    Gmtime64,
    Localtime,
    Localtime64,
    Mktime,
    Mktime64,
    Strftime,
    Time,
    Time64,
)
from ..systemv import ArmV7EMSysVModel


class ArmV7EMSysVTime(Time, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVLocaltime(Localtime, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVGmtime(Gmtime, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVCtime(Ctime, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVAsctime(Asctime, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVStrftime(Strftime, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVDifftime(Difftime, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVMktime(Mktime, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVClock(Clock, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVTime64(Time64, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVLocaltime64(Localtime64, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVGmtime64(Gmtime64, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVCtime64(Ctime64, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVDifftime64(Difftime64, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVMktime64(Mktime64, ArmV7EMSysVModel):
    pass


__all__ = [
    "ArmV7EMSysVTime",
    "ArmV7EMSysVLocaltime",
    "ArmV7EMSysVGmtime",
    "ArmV7EMSysVCtime",
    "ArmV7EMSysVAsctime",
    "ArmV7EMSysVStrftime",
    "ArmV7EMSysVDifftime",
    "ArmV7EMSysVMktime",
    "ArmV7EMSysVClock",
    "ArmV7EMSysVTime64",
    "ArmV7EMSysVLocaltime64",
    "ArmV7EMSysVGmtime64",
    "ArmV7EMSysVCtime64",
    "ArmV7EMSysVDifftime64",
    "ArmV7EMSysVMktime64",
]
