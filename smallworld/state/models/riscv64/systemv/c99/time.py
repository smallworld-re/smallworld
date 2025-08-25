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
from ..systemv import RiscV64SysVModel


class RiscV64SysVTime(Time, RiscV64SysVModel):
    pass


class RiscV64SysVLocaltime(Localtime, RiscV64SysVModel):
    pass


class RiscV64SysVGmtime(Gmtime, RiscV64SysVModel):
    pass


class RiscV64SysVCtime(Ctime, RiscV64SysVModel):
    pass


class RiscV64SysVAsctime(Asctime, RiscV64SysVModel):
    pass


class RiscV64SysVStrftime(Strftime, RiscV64SysVModel):
    pass


class RiscV64SysVDifftime(Difftime, RiscV64SysVModel):
    pass


class RiscV64SysVMktime(Mktime, RiscV64SysVModel):
    pass


class RiscV64SysVClock(Clock, RiscV64SysVModel):
    pass


__all__ = [
    "RiscV64SysVTime",
    "RiscV64SysVLocaltime",
    "RiscV64SysVGmtime",
    "RiscV64SysVCtime",
    "RiscV64SysVAsctime",
    "RiscV64SysVStrftime",
    "RiscV64SysVDifftime",
    "RiscV64SysVMktime",
    "RiscV64SysVClock",
]
