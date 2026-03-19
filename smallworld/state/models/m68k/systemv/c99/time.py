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
from ..systemv import M68KSysVModel


class M68KSysVTime(Time, M68KSysVModel):
    pass


class M68KSysVLocaltime(Localtime, M68KSysVModel):
    pass


class M68KSysVGmtime(Gmtime, M68KSysVModel):
    pass


class M68KSysVCtime(Ctime, M68KSysVModel):
    pass


class M68KSysVAsctime(Asctime, M68KSysVModel):
    pass


class M68KSysVStrftime(Strftime, M68KSysVModel):
    pass


class M68KSysVDifftime(Difftime, M68KSysVModel):
    pass


class M68KSysVMktime(Mktime, M68KSysVModel):
    pass


class M68KSysVClock(Clock, M68KSysVModel):
    pass


__all__ = [
    "M68KSysVTime",
    "M68KSysVLocaltime",
    "M68KSysVGmtime",
    "M68KSysVCtime",
    "M68KSysVAsctime",
    "M68KSysVStrftime",
    "M68KSysVDifftime",
    "M68KSysVMktime",
    "M68KSysVClock",
]
