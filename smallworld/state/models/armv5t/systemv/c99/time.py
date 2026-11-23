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
from ..systemv import ArmV5TSysVModel


class ArmV5TSysVTime(Time, ArmV5TSysVModel):
    pass


class ArmV5TSysVLocaltime(Localtime, ArmV5TSysVModel):
    pass


class ArmV5TSysVGmtime(Gmtime, ArmV5TSysVModel):
    pass


class ArmV5TSysVCtime(Ctime, ArmV5TSysVModel):
    pass


class ArmV5TSysVAsctime(Asctime, ArmV5TSysVModel):
    pass


class ArmV5TSysVStrftime(Strftime, ArmV5TSysVModel):
    pass


class ArmV5TSysVDifftime(Difftime, ArmV5TSysVModel):
    pass


class ArmV5TSysVMktime(Mktime, ArmV5TSysVModel):
    pass


class ArmV5TSysVClock(Clock, ArmV5TSysVModel):
    pass


__all__ = [
    "ArmV5TSysVTime",
    "ArmV5TSysVLocaltime",
    "ArmV5TSysVGmtime",
    "ArmV5TSysVCtime",
    "ArmV5TSysVAsctime",
    "ArmV5TSysVStrftime",
    "ArmV5TSysVDifftime",
    "ArmV5TSysVMktime",
    "ArmV5TSysVClock",
]
