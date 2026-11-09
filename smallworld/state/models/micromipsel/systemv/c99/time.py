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
from ..systemv import MicroMIPSELSysVModel


class MicroMIPSELSysVTime(Time, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVLocaltime(Localtime, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVGmtime(Gmtime, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVCtime(Ctime, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVAsctime(Asctime, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVStrftime(Strftime, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVDifftime(Difftime, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVMktime(Mktime, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVClock(Clock, MicroMIPSELSysVModel):
    pass


__all__ = [
    "MicroMIPSELSysVTime",
    "MicroMIPSELSysVLocaltime",
    "MicroMIPSELSysVGmtime",
    "MicroMIPSELSysVCtime",
    "MicroMIPSELSysVAsctime",
    "MicroMIPSELSysVStrftime",
    "MicroMIPSELSysVDifftime",
    "MicroMIPSELSysVMktime",
    "MicroMIPSELSysVClock",
]
