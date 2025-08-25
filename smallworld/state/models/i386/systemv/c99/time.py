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
from ..systemv import I386SysVModel


class I386SysVTime(Time, I386SysVModel):
    pass


class I386SysVLocaltime(Localtime, I386SysVModel):
    pass


class I386SysVGmtime(Gmtime, I386SysVModel):
    pass


class I386SysVCtime(Ctime, I386SysVModel):
    pass


class I386SysVAsctime(Asctime, I386SysVModel):
    pass


class I386SysVStrftime(Strftime, I386SysVModel):
    pass


class I386SysVDifftime(Difftime, I386SysVModel):
    pass


class I386SysVMktime(Mktime, I386SysVModel):
    pass


class I386SysVClock(Clock, I386SysVModel):
    pass


__all__ = [
    "I386SysVTime",
    "I386SysVLocaltime",
    "I386SysVGmtime",
    "I386SysVCtime",
    "I386SysVAsctime",
    "I386SysVStrftime",
    "I386SysVDifftime",
    "I386SysVMktime",
    "I386SysVClock",
]
