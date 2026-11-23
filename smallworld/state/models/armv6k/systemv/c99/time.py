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
from ..systemv import ArmV6KSysVModel


class ArmV6KSysVTime(Time, ArmV6KSysVModel):
    pass


class ArmV6KSysVLocaltime(Localtime, ArmV6KSysVModel):
    pass


class ArmV6KSysVGmtime(Gmtime, ArmV6KSysVModel):
    pass


class ArmV6KSysVCtime(Ctime, ArmV6KSysVModel):
    pass


class ArmV6KSysVAsctime(Asctime, ArmV6KSysVModel):
    pass


class ArmV6KSysVStrftime(Strftime, ArmV6KSysVModel):
    pass


class ArmV6KSysVDifftime(Difftime, ArmV6KSysVModel):
    pass


class ArmV6KSysVMktime(Mktime, ArmV6KSysVModel):
    pass


class ArmV6KSysVClock(Clock, ArmV6KSysVModel):
    pass


__all__ = [
    "ArmV6KSysVTime",
    "ArmV6KSysVLocaltime",
    "ArmV6KSysVGmtime",
    "ArmV6KSysVCtime",
    "ArmV6KSysVAsctime",
    "ArmV6KSysVStrftime",
    "ArmV6KSysVDifftime",
    "ArmV6KSysVMktime",
    "ArmV6KSysVClock",
]
