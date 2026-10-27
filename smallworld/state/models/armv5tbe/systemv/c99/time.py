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
from ..systemv import ArmV5TBESysVModel


class ArmV5TBESysVTime(Time, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVLocaltime(Localtime, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVGmtime(Gmtime, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVCtime(Ctime, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVAsctime(Asctime, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVStrftime(Strftime, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVDifftime(Difftime, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVMktime(Mktime, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVClock(Clock, ArmV5TBESysVModel):
    pass


__all__ = [
    "ArmV5TBESysVTime",
    "ArmV5TBESysVLocaltime",
    "ArmV5TBESysVGmtime",
    "ArmV5TBESysVCtime",
    "ArmV5TBESysVAsctime",
    "ArmV5TBESysVStrftime",
    "ArmV5TBESysVDifftime",
    "ArmV5TBESysVMktime",
    "ArmV5TBESysVClock",
]
