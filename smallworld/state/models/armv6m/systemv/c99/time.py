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
from ..systemv import ArmV6MSysVModel


class ArmV6MSysVTime(Time, ArmV6MSysVModel):
    pass


class ArmV6MSysVLocaltime(Localtime, ArmV6MSysVModel):
    pass


class ArmV6MSysVGmtime(Gmtime, ArmV6MSysVModel):
    pass


class ArmV6MSysVCtime(Ctime, ArmV6MSysVModel):
    pass


class ArmV6MSysVAsctime(Asctime, ArmV6MSysVModel):
    pass


class ArmV6MSysVStrftime(Strftime, ArmV6MSysVModel):
    pass


class ArmV6MSysVDifftime(Difftime, ArmV6MSysVModel):
    pass


class ArmV6MSysVMktime(Mktime, ArmV6MSysVModel):
    pass


class ArmV6MSysVClock(Clock, ArmV6MSysVModel):
    pass


__all__ = [
    "ArmV6MSysVTime",
    "ArmV6MSysVLocaltime",
    "ArmV6MSysVGmtime",
    "ArmV6MSysVCtime",
    "ArmV6MSysVAsctime",
    "ArmV6MSysVStrftime",
    "ArmV6MSysVDifftime",
    "ArmV6MSysVMktime",
    "ArmV6MSysVClock",
]
