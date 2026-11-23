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
from ..systemv import ArmV8RSysVModel


class ArmV8RSysVTime(Time, ArmV8RSysVModel):
    pass


class ArmV8RSysVLocaltime(Localtime, ArmV8RSysVModel):
    pass


class ArmV8RSysVGmtime(Gmtime, ArmV8RSysVModel):
    pass


class ArmV8RSysVCtime(Ctime, ArmV8RSysVModel):
    pass


class ArmV8RSysVAsctime(Asctime, ArmV8RSysVModel):
    pass


class ArmV8RSysVStrftime(Strftime, ArmV8RSysVModel):
    pass


class ArmV8RSysVDifftime(Difftime, ArmV8RSysVModel):
    pass


class ArmV8RSysVMktime(Mktime, ArmV8RSysVModel):
    pass


class ArmV8RSysVClock(Clock, ArmV8RSysVModel):
    pass


__all__ = [
    "ArmV8RSysVTime",
    "ArmV8RSysVLocaltime",
    "ArmV8RSysVGmtime",
    "ArmV8RSysVCtime",
    "ArmV8RSysVAsctime",
    "ArmV8RSysVStrftime",
    "ArmV8RSysVDifftime",
    "ArmV8RSysVMktime",
    "ArmV8RSysVClock",
]
