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
from ..systemv import ArmV7ABESysVModel


class ArmV7ABESysVTime(Time, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVLocaltime(Localtime, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVGmtime(Gmtime, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVCtime(Ctime, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVAsctime(Asctime, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVStrftime(Strftime, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVDifftime(Difftime, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVMktime(Mktime, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVClock(Clock, ArmV7ABESysVModel):
    pass


__all__ = [
    "ArmV7ABESysVTime",
    "ArmV7ABESysVLocaltime",
    "ArmV7ABESysVGmtime",
    "ArmV7ABESysVCtime",
    "ArmV7ABESysVAsctime",
    "ArmV7ABESysVStrftime",
    "ArmV7ABESysVDifftime",
    "ArmV7ABESysVMktime",
    "ArmV7ABESysVClock",
]
