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
from ..systemv import ArmV7ASysVModel


class ArmV7ASysVTime(Time, ArmV7ASysVModel):
    pass


class ArmV7ASysVLocaltime(Localtime, ArmV7ASysVModel):
    pass


class ArmV7ASysVGmtime(Gmtime, ArmV7ASysVModel):
    pass


class ArmV7ASysVCtime(Ctime, ArmV7ASysVModel):
    pass


class ArmV7ASysVAsctime(Asctime, ArmV7ASysVModel):
    pass


class ArmV7ASysVStrftime(Strftime, ArmV7ASysVModel):
    pass


class ArmV7ASysVDifftime(Difftime, ArmV7ASysVModel):
    pass


class ArmV7ASysVMktime(Mktime, ArmV7ASysVModel):
    pass


class ArmV7ASysVClock(Clock, ArmV7ASysVModel):
    pass


__all__ = [
    "ArmV7ASysVTime",
    "ArmV7ASysVLocaltime",
    "ArmV7ASysVGmtime",
    "ArmV7ASysVCtime",
    "ArmV7ASysVAsctime",
    "ArmV7ASysVStrftime",
    "ArmV7ASysVDifftime",
    "ArmV7ASysVMktime",
    "ArmV7ASysVClock",
]
