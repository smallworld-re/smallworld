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
from ..systemv import ArmV7MSysVModel


class ArmV7MSysVTime(Time, ArmV7MSysVModel):
    pass


class ArmV7MSysVLocaltime(Localtime, ArmV7MSysVModel):
    pass


class ArmV7MSysVGmtime(Gmtime, ArmV7MSysVModel):
    pass


class ArmV7MSysVCtime(Ctime, ArmV7MSysVModel):
    pass


class ArmV7MSysVAsctime(Asctime, ArmV7MSysVModel):
    pass


class ArmV7MSysVStrftime(Strftime, ArmV7MSysVModel):
    pass


class ArmV7MSysVDifftime(Difftime, ArmV7MSysVModel):
    pass


class ArmV7MSysVMktime(Mktime, ArmV7MSysVModel):
    pass


class ArmV7MSysVClock(Clock, ArmV7MSysVModel):
    pass


__all__ = [
    "ArmV7MSysVTime",
    "ArmV7MSysVLocaltime",
    "ArmV7MSysVGmtime",
    "ArmV7MSysVCtime",
    "ArmV7MSysVAsctime",
    "ArmV7MSysVStrftime",
    "ArmV7MSysVDifftime",
    "ArmV7MSysVMktime",
    "ArmV7MSysVClock",
]
