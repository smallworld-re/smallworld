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
from ..systemv import SPARC32SysVModel


class SPARC32SysVTime(Time, SPARC32SysVModel):
    pass


class SPARC32SysVLocaltime(Localtime, SPARC32SysVModel):
    pass


class SPARC32SysVGmtime(Gmtime, SPARC32SysVModel):
    pass


class SPARC32SysVCtime(Ctime, SPARC32SysVModel):
    pass


class SPARC32SysVAsctime(Asctime, SPARC32SysVModel):
    pass


class SPARC32SysVStrftime(Strftime, SPARC32SysVModel):
    pass


class SPARC32SysVDifftime(Difftime, SPARC32SysVModel):
    pass


class SPARC32SysVMktime(Mktime, SPARC32SysVModel):
    pass


class SPARC32SysVClock(Clock, SPARC32SysVModel):
    pass


__all__ = [
    "SPARC32SysVTime",
    "SPARC32SysVLocaltime",
    "SPARC32SysVGmtime",
    "SPARC32SysVCtime",
    "SPARC32SysVAsctime",
    "SPARC32SysVStrftime",
    "SPARC32SysVDifftime",
    "SPARC32SysVMktime",
    "SPARC32SysVClock",
]
