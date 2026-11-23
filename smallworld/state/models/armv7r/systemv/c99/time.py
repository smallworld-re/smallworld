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
from ..systemv import ArmV7RSysVModel


class ArmV7RSysVTime(Time, ArmV7RSysVModel):
    pass


class ArmV7RSysVLocaltime(Localtime, ArmV7RSysVModel):
    pass


class ArmV7RSysVGmtime(Gmtime, ArmV7RSysVModel):
    pass


class ArmV7RSysVCtime(Ctime, ArmV7RSysVModel):
    pass


class ArmV7RSysVAsctime(Asctime, ArmV7RSysVModel):
    pass


class ArmV7RSysVStrftime(Strftime, ArmV7RSysVModel):
    pass


class ArmV7RSysVDifftime(Difftime, ArmV7RSysVModel):
    pass


class ArmV7RSysVMktime(Mktime, ArmV7RSysVModel):
    pass


class ArmV7RSysVClock(Clock, ArmV7RSysVModel):
    pass


__all__ = [
    "ArmV7RSysVTime",
    "ArmV7RSysVLocaltime",
    "ArmV7RSysVGmtime",
    "ArmV7RSysVCtime",
    "ArmV7RSysVAsctime",
    "ArmV7RSysVStrftime",
    "ArmV7RSysVDifftime",
    "ArmV7RSysVMktime",
    "ArmV7RSysVClock",
]
