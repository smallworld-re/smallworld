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
from ..systemv import MIPS64SysVModel


class MIPS64SysVTime(Time, MIPS64SysVModel):
    pass


class MIPS64SysVLocaltime(Localtime, MIPS64SysVModel):
    pass


class MIPS64SysVGmtime(Gmtime, MIPS64SysVModel):
    pass


class MIPS64SysVCtime(Ctime, MIPS64SysVModel):
    pass


class MIPS64SysVAsctime(Asctime, MIPS64SysVModel):
    pass


class MIPS64SysVStrftime(Strftime, MIPS64SysVModel):
    pass


class MIPS64SysVDifftime(Difftime, MIPS64SysVModel):
    pass


class MIPS64SysVMktime(Mktime, MIPS64SysVModel):
    pass


class MIPS64SysVClock(Clock, MIPS64SysVModel):
    pass


__all__ = [
    "MIPS64SysVTime",
    "MIPS64SysVLocaltime",
    "MIPS64SysVGmtime",
    "MIPS64SysVCtime",
    "MIPS64SysVAsctime",
    "MIPS64SysVStrftime",
    "MIPS64SysVDifftime",
    "MIPS64SysVMktime",
    "MIPS64SysVClock",
]
