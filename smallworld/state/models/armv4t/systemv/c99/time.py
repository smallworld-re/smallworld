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
from ..systemv import ArmV4TSysVModel


class ArmV4TSysVTime(Time, ArmV4TSysVModel):
    pass


class ArmV4TSysVLocaltime(Localtime, ArmV4TSysVModel):
    pass


class ArmV4TSysVGmtime(Gmtime, ArmV4TSysVModel):
    pass


class ArmV4TSysVCtime(Ctime, ArmV4TSysVModel):
    pass


class ArmV4TSysVAsctime(Asctime, ArmV4TSysVModel):
    pass


class ArmV4TSysVStrftime(Strftime, ArmV4TSysVModel):
    pass


class ArmV4TSysVDifftime(Difftime, ArmV4TSysVModel):
    pass


class ArmV4TSysVMktime(Mktime, ArmV4TSysVModel):
    pass


class ArmV4TSysVClock(Clock, ArmV4TSysVModel):
    pass


__all__ = [
    "ArmV4TSysVTime",
    "ArmV4TSysVLocaltime",
    "ArmV4TSysVGmtime",
    "ArmV4TSysVCtime",
    "ArmV4TSysVAsctime",
    "ArmV4TSysVStrftime",
    "ArmV4TSysVDifftime",
    "ArmV4TSysVMktime",
    "ArmV4TSysVClock",
]
