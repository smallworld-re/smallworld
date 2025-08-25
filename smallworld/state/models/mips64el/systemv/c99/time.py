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
from ..systemv import MIPS64ELSysVModel


class MIPS64ELSysVTime(Time, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVLocaltime(Localtime, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVGmtime(Gmtime, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVCtime(Ctime, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVAsctime(Asctime, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVStrftime(Strftime, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVDifftime(Difftime, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVMktime(Mktime, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVClock(Clock, MIPS64ELSysVModel):
    pass


__all__ = [
    "MIPS64ELSysVTime",
    "MIPS64ELSysVLocaltime",
    "MIPS64ELSysVGmtime",
    "MIPS64ELSysVCtime",
    "MIPS64ELSysVAsctime",
    "MIPS64ELSysVStrftime",
    "MIPS64ELSysVDifftime",
    "MIPS64ELSysVMktime",
    "MIPS64ELSysVClock",
]
