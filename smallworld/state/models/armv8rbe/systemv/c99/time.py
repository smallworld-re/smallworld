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
from ..systemv import ArmV8RBESysVModel


class ArmV8RBESysVTime(Time, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVLocaltime(Localtime, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVGmtime(Gmtime, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVCtime(Ctime, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVAsctime(Asctime, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVStrftime(Strftime, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVDifftime(Difftime, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVMktime(Mktime, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVClock(Clock, ArmV8RBESysVModel):
    pass


__all__ = [
    "ArmV8RBESysVTime",
    "ArmV8RBESysVLocaltime",
    "ArmV8RBESysVGmtime",
    "ArmV8RBESysVCtime",
    "ArmV8RBESysVAsctime",
    "ArmV8RBESysVStrftime",
    "ArmV8RBESysVDifftime",
    "ArmV8RBESysVMktime",
    "ArmV8RBESysVClock",
]
