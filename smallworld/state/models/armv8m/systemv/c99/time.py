from ....c99 import (
    Asctime,
    Clock,
    Ctime,
    Ctime64,
    Difftime,
    Difftime64,
    Gmtime,
    Gmtime64,
    Localtime,
    Localtime64,
    Mktime,
    Mktime64,
    Strftime,
    Time,
    Time64,
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


class ArmV8MSysVTime64(Time64, ArmV8MSysVModel):
    pass


class ArmV8MSysVLocaltime64(Localtime64, ArmV8MSysVModel):
    pass


class ArmV8MSysVGmtime64(Gmtime64, ArmV8MSysVModel):
    pass


class ArmV8MSysVCtime64(Ctime64, ArmV8MSysVModel):
    pass


class ArmV8MSysVDifftime64(Difftime64, ArmV8MSysVModel):
    pass


class ArmV8MSysVMktime64(Mktime64, ArmV8MSysVModel):
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
    "ArmV8MSysVTime64",
    "ArmV8MSysVLocaltime64",
    "ArmV8MSysVGmtime64",
    "ArmV8MSysVCtime64",
    "ArmV8MSysVDifftime64",
    "ArmV8MSysVMktime64",
]
