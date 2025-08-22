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
from ..systemv import PowerPCSysVModel


class PowerPCSysVTime(Time, PowerPCSysVModel):
    pass


class PowerPCSysVLocaltime(Localtime, PowerPCSysVModel):
    pass


class PowerPCSysVGmtime(Gmtime, PowerPCSysVModel):
    pass


class PowerPCSysVCtime(Ctime, PowerPCSysVModel):
    pass


class PowerPCSysVAsctime(Asctime, PowerPCSysVModel):
    pass


class PowerPCSysVStrftime(Strftime, PowerPCSysVModel):
    pass


class PowerPCSysVDifftime(Difftime, PowerPCSysVModel):
    pass


class PowerPCSysVMktime(Mktime, PowerPCSysVModel):
    pass


class PowerPCSysVClock(Clock, PowerPCSysVModel):
    pass


__all__ = [
    "PowerPCSysVTime",
    "PowerPCSysVLocaltime",
    "PowerPCSysVGmtime",
    "PowerPCSysVCtime",
    "PowerPCSysVAsctime",
    "PowerPCSysVStrftime",
    "PowerPCSysVDifftime",
    "PowerPCSysVMktime",
    "PowerPCSysVClock",
]
