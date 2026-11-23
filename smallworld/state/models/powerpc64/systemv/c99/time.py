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
from ..systemv import PowerPC64SysVModel


class PowerPC64SysVTime(Time, PowerPC64SysVModel):
    pass


class PowerPC64SysVLocaltime(Localtime, PowerPC64SysVModel):
    pass


class PowerPC64SysVGmtime(Gmtime, PowerPC64SysVModel):
    pass


class PowerPC64SysVCtime(Ctime, PowerPC64SysVModel):
    pass


class PowerPC64SysVAsctime(Asctime, PowerPC64SysVModel):
    pass


class PowerPC64SysVStrftime(Strftime, PowerPC64SysVModel):
    pass


class PowerPC64SysVDifftime(Difftime, PowerPC64SysVModel):
    pass


class PowerPC64SysVMktime(Mktime, PowerPC64SysVModel):
    pass


class PowerPC64SysVClock(Clock, PowerPC64SysVModel):
    pass


__all__ = [
    "PowerPC64SysVTime",
    "PowerPC64SysVLocaltime",
    "PowerPC64SysVGmtime",
    "PowerPC64SysVCtime",
    "PowerPC64SysVAsctime",
    "PowerPC64SysVStrftime",
    "PowerPC64SysVDifftime",
    "PowerPC64SysVMktime",
    "PowerPC64SysVClock",
]
