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
from ..systemv import ArmV6KBESysVModel


class ArmV6KBESysVTime(Time, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVLocaltime(Localtime, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVGmtime(Gmtime, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVCtime(Ctime, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVAsctime(Asctime, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVStrftime(Strftime, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVDifftime(Difftime, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVMktime(Mktime, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVClock(Clock, ArmV6KBESysVModel):
    pass


__all__ = [
    "ArmV6KBESysVTime",
    "ArmV6KBESysVLocaltime",
    "ArmV6KBESysVGmtime",
    "ArmV6KBESysVCtime",
    "ArmV6KBESysVAsctime",
    "ArmV6KBESysVStrftime",
    "ArmV6KBESysVDifftime",
    "ArmV6KBESysVMktime",
    "ArmV6KBESysVClock",
]
