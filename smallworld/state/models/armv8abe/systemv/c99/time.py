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
from ..systemv import ArmV8ABESysVModel


class ArmV8ABESysVTime(Time, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVLocaltime(Localtime, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVGmtime(Gmtime, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVCtime(Ctime, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVAsctime(Asctime, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVStrftime(Strftime, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVDifftime(Difftime, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVMktime(Mktime, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVClock(Clock, ArmV8ABESysVModel):
    pass


__all__ = [
    "ArmV8ABESysVTime",
    "ArmV8ABESysVLocaltime",
    "ArmV8ABESysVGmtime",
    "ArmV8ABESysVCtime",
    "ArmV8ABESysVAsctime",
    "ArmV8ABESysVStrftime",
    "ArmV8ABESysVDifftime",
    "ArmV8ABESysVMktime",
    "ArmV8ABESysVClock",
]
