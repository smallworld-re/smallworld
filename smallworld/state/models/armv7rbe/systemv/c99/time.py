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
from ..systemv import ArmV7RBESysVModel


class ArmV7RBESysVTime(Time, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVLocaltime(Localtime, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVGmtime(Gmtime, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVCtime(Ctime, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVAsctime(Asctime, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVStrftime(Strftime, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVDifftime(Difftime, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVMktime(Mktime, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVClock(Clock, ArmV7RBESysVModel):
    pass


__all__ = [
    "ArmV7RBESysVTime",
    "ArmV7RBESysVLocaltime",
    "ArmV7RBESysVGmtime",
    "ArmV7RBESysVCtime",
    "ArmV7RBESysVAsctime",
    "ArmV7RBESysVStrftime",
    "ArmV7RBESysVDifftime",
    "ArmV7RBESysVMktime",
    "ArmV7RBESysVClock",
]
