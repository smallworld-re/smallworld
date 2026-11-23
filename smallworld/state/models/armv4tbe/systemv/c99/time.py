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
from ..systemv import ArmV4TBESysVModel


class ArmV4TBESysVTime(Time, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVLocaltime(Localtime, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVGmtime(Gmtime, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVCtime(Ctime, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVAsctime(Asctime, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVStrftime(Strftime, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVDifftime(Difftime, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVMktime(Mktime, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVClock(Clock, ArmV4TBESysVModel):
    pass


__all__ = [
    "ArmV4TBESysVTime",
    "ArmV4TBESysVLocaltime",
    "ArmV4TBESysVGmtime",
    "ArmV4TBESysVCtime",
    "ArmV4TBESysVAsctime",
    "ArmV4TBESysVStrftime",
    "ArmV4TBESysVDifftime",
    "ArmV4TBESysVMktime",
    "ArmV4TBESysVClock",
]
