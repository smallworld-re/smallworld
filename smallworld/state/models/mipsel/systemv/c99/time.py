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
from ..systemv import MIPSELSysVModel


class MIPSELSysVTime(Time, MIPSELSysVModel):
    pass


class MIPSELSysVLocaltime(Localtime, MIPSELSysVModel):
    pass


class MIPSELSysVGmtime(Gmtime, MIPSELSysVModel):
    pass


class MIPSELSysVCtime(Ctime, MIPSELSysVModel):
    pass


class MIPSELSysVAsctime(Asctime, MIPSELSysVModel):
    pass


class MIPSELSysVStrftime(Strftime, MIPSELSysVModel):
    pass


class MIPSELSysVDifftime(Difftime, MIPSELSysVModel):
    pass


class MIPSELSysVMktime(Mktime, MIPSELSysVModel):
    pass


class MIPSELSysVClock(Clock, MIPSELSysVModel):
    pass


__all__ = [
    "MIPSELSysVTime",
    "MIPSELSysVLocaltime",
    "MIPSELSysVGmtime",
    "MIPSELSysVCtime",
    "MIPSELSysVAsctime",
    "MIPSELSysVStrftime",
    "MIPSELSysVDifftime",
    "MIPSELSysVMktime",
    "MIPSELSysVClock",
]
