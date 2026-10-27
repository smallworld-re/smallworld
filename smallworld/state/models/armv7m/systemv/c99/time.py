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


class ArmV7MSysVTime64(Time64, ArmV7MSysVModel):
    pass


class ArmV7MSysVLocaltime64(Localtime64, ArmV7MSysVModel):
    pass


class ArmV7MSysVGmtime64(Gmtime64, ArmV7MSysVModel):
    pass


class ArmV7MSysVCtime64(Ctime64, ArmV7MSysVModel):
    pass


class ArmV7MSysVDifftime64(Difftime64, ArmV7MSysVModel):
    pass


class ArmV7MSysVMktime64(Mktime64, ArmV7MSysVModel):
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
    "ArmV7MSysVTime64",
    "ArmV7MSysVLocaltime64",
    "ArmV7MSysVGmtime64",
    "ArmV7MSysVCtime64",
    "ArmV7MSysVDifftime64",
    "ArmV7MSysVMktime64",
]
