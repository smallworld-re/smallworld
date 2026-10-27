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


class ArmV6MSysVTime64(Time64, ArmV6MSysVModel):
    pass


class ArmV6MSysVLocaltime64(Localtime64, ArmV6MSysVModel):
    pass


class ArmV6MSysVGmtime64(Gmtime64, ArmV6MSysVModel):
    pass


class ArmV6MSysVCtime64(Ctime64, ArmV6MSysVModel):
    pass


class ArmV6MSysVDifftime64(Difftime64, ArmV6MSysVModel):
    pass


class ArmV6MSysVMktime64(Mktime64, ArmV6MSysVModel):
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
    "ArmV6MSysVTime64",
    "ArmV6MSysVLocaltime64",
    "ArmV6MSysVGmtime64",
    "ArmV6MSysVCtime64",
    "ArmV6MSysVDifftime64",
    "ArmV6MSysVMktime64",
]
