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
from ..systemv import LoongArch64SysVModel


class LoongArch64SysVTime(Time, LoongArch64SysVModel):
    pass


class LoongArch64SysVLocaltime(Localtime, LoongArch64SysVModel):
    pass


class LoongArch64SysVGmtime(Gmtime, LoongArch64SysVModel):
    pass


class LoongArch64SysVCtime(Ctime, LoongArch64SysVModel):
    pass


class LoongArch64SysVAsctime(Asctime, LoongArch64SysVModel):
    pass


class LoongArch64SysVStrftime(Strftime, LoongArch64SysVModel):
    pass


class LoongArch64SysVDifftime(Difftime, LoongArch64SysVModel):
    pass


class LoongArch64SysVMktime(Mktime, LoongArch64SysVModel):
    pass


class LoongArch64SysVClock(Clock, LoongArch64SysVModel):
    pass


__all__ = [
    "LoongArch64SysVTime",
    "LoongArch64SysVLocaltime",
    "LoongArch64SysVGmtime",
    "LoongArch64SysVCtime",
    "LoongArch64SysVAsctime",
    "LoongArch64SysVStrftime",
    "LoongArch64SysVDifftime",
    "LoongArch64SysVMktime",
    "LoongArch64SysVClock",
]
