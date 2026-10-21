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
from ..systemv import ArmV8MSysVModel


class ArmV8MSysVTime(Time, ArmV8MSysVModel):
    pass


class ArmV8MSysVLocaltime(Localtime, ArmV8MSysVModel):
    pass


class ArmV8MSysVGmtime(Gmtime, ArmV8MSysVModel):
    pass


class ArmV8MSysVCtime(Ctime, ArmV8MSysVModel):
    pass


class ArmV8MSysVAsctime(Asctime, ArmV8MSysVModel):
    pass


class ArmV8MSysVStrftime(Strftime, ArmV8MSysVModel):
    pass


class ArmV8MSysVDifftime(Difftime, ArmV8MSysVModel):
    pass


class ArmV8MSysVMktime(Mktime, ArmV8MSysVModel):
    pass


class ArmV8MSysVClock(Clock, ArmV8MSysVModel):
    pass


__all__ = [
    "ArmV8MSysVTime",
    "ArmV8MSysVLocaltime",
    "ArmV8MSysVGmtime",
    "ArmV8MSysVCtime",
    "ArmV8MSysVAsctime",
    "ArmV8MSysVStrftime",
    "ArmV8MSysVDifftime",
    "ArmV8MSysVMktime",
    "ArmV8MSysVClock",
]
