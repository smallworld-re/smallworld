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
from ..systemv import AArch64SysVModel


class AArch64SysVTime(Time, AArch64SysVModel):
    pass


class AArch64SysVLocaltime(Localtime, AArch64SysVModel):
    pass


class AArch64SysVGmtime(Gmtime, AArch64SysVModel):
    pass


class AArch64SysVCtime(Ctime, AArch64SysVModel):
    pass


class AArch64SysVAsctime(Asctime, AArch64SysVModel):
    pass


class AArch64SysVStrftime(Strftime, AArch64SysVModel):
    pass


class AArch64SysVDifftime(Difftime, AArch64SysVModel):
    pass


class AArch64SysVMktime(Mktime, AArch64SysVModel):
    pass


class AArch64SysVClock(Clock, AArch64SysVModel):
    pass


__all__ = [
    "AArch64SysVTime",
    "AArch64SysVLocaltime",
    "AArch64SysVGmtime",
    "AArch64SysVCtime",
    "AArch64SysVAsctime",
    "AArch64SysVStrftime",
    "AArch64SysVDifftime",
    "AArch64SysVMktime",
    "AArch64SysVClock",
]
