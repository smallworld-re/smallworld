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
]
