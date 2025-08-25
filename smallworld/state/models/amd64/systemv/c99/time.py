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
from ..systemv import AMD64SysVModel


class AMD64SysVTime(Time, AMD64SysVModel):
    pass


class AMD64SysVLocaltime(Localtime, AMD64SysVModel):
    pass


class AMD64SysVGmtime(Gmtime, AMD64SysVModel):
    pass


class AMD64SysVCtime(Ctime, AMD64SysVModel):
    pass


class AMD64SysVAsctime(Asctime, AMD64SysVModel):
    pass


class AMD64SysVStrftime(Strftime, AMD64SysVModel):
    pass


class AMD64SysVDifftime(Difftime, AMD64SysVModel):
    pass


class AMD64SysVMktime(Mktime, AMD64SysVModel):
    pass


class AMD64SysVClock(Clock, AMD64SysVModel):
    pass


__all__ = [
    "AMD64SysVTime",
    "AMD64SysVLocaltime",
    "AMD64SysVGmtime",
    "AMD64SysVCtime",
    "AMD64SysVAsctime",
    "AMD64SysVStrftime",
    "AMD64SysVDifftime",
    "AMD64SysVMktime",
    "AMD64SysVClock",
]
