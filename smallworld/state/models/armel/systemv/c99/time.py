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
from ..systemv import ArmELSysVModel


class ArmELSysVTime(Time, ArmELSysVModel):
    pass


class ArmELSysVLocaltime(Localtime, ArmELSysVModel):
    pass


class ArmELSysVGmtime(Gmtime, ArmELSysVModel):
    pass


class ArmELSysVCtime(Ctime, ArmELSysVModel):
    pass


class ArmELSysVAsctime(Asctime, ArmELSysVModel):
    pass


class ArmELSysVStrftime(Strftime, ArmELSysVModel):
    pass


class ArmELSysVDifftime(Difftime, ArmELSysVModel):
    pass


class ArmELSysVMktime(Mktime, ArmELSysVModel):
    pass


class ArmELSysVClock(Clock, ArmELSysVModel):
    pass


__all__ = [
    "ArmELSysVTime",
    "ArmELSysVLocaltime",
    "ArmELSysVGmtime",
    "ArmELSysVCtime",
    "ArmELSysVAsctime",
    "ArmELSysVStrftime",
    "ArmELSysVDifftime",
    "ArmELSysVMktime",
    "ArmELSysVClock",
]
