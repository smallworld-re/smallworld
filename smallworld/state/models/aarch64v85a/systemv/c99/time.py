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
from ..systemv import AArch64V85ASysVModel


class AArch64V85ASysVTime(Time, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVLocaltime(Localtime, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVGmtime(Gmtime, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVCtime(Ctime, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVAsctime(Asctime, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVStrftime(Strftime, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVDifftime(Difftime, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVMktime(Mktime, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVClock(Clock, AArch64V85ASysVModel):
    pass


__all__ = [
    "AArch64V85ASysVTime",
    "AArch64V85ASysVLocaltime",
    "AArch64V85ASysVGmtime",
    "AArch64V85ASysVCtime",
    "AArch64V85ASysVAsctime",
    "AArch64V85ASysVStrftime",
    "AArch64V85ASysVDifftime",
    "AArch64V85ASysVMktime",
    "AArch64V85ASysVClock",
]
