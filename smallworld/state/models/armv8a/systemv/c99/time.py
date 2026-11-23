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
from ..systemv import ArmV8ASysVModel


class ArmV8ASysVTime(Time, ArmV8ASysVModel):
    pass


class ArmV8ASysVLocaltime(Localtime, ArmV8ASysVModel):
    pass


class ArmV8ASysVGmtime(Gmtime, ArmV8ASysVModel):
    pass


class ArmV8ASysVCtime(Ctime, ArmV8ASysVModel):
    pass


class ArmV8ASysVAsctime(Asctime, ArmV8ASysVModel):
    pass


class ArmV8ASysVStrftime(Strftime, ArmV8ASysVModel):
    pass


class ArmV8ASysVDifftime(Difftime, ArmV8ASysVModel):
    pass


class ArmV8ASysVMktime(Mktime, ArmV8ASysVModel):
    pass


class ArmV8ASysVClock(Clock, ArmV8ASysVModel):
    pass


__all__ = [
    "ArmV8ASysVTime",
    "ArmV8ASysVLocaltime",
    "ArmV8ASysVGmtime",
    "ArmV8ASysVCtime",
    "ArmV8ASysVAsctime",
    "ArmV8ASysVStrftime",
    "ArmV8ASysVDifftime",
    "ArmV8ASysVMktime",
    "ArmV8ASysVClock",
]
