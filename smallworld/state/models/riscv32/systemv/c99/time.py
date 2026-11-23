# glibc gave RiscV32 a 64-bit time_t from the start.
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
from ....cstd import ArgumentType
from ..systemv import RiscV32SysVModel


class RiscV32SysVTime(Time, RiscV32SysVModel):
    time_t = ArgumentType.LONGLONG
    return_type = ArgumentType.LONGLONG


class RiscV32SysVLocaltime(Localtime, RiscV32SysVModel):
    time_t = ArgumentType.LONGLONG


class RiscV32SysVGmtime(Gmtime, RiscV32SysVModel):
    time_t = ArgumentType.LONGLONG


class RiscV32SysVCtime(Ctime, RiscV32SysVModel):
    time_t = ArgumentType.LONGLONG


class RiscV32SysVAsctime(Asctime, RiscV32SysVModel):
    pass


class RiscV32SysVStrftime(Strftime, RiscV32SysVModel):
    pass


class RiscV32SysVDifftime(Difftime, RiscV32SysVModel):
    time_t = ArgumentType.LONGLONG
    argument_types = [ArgumentType.LONGLONG, ArgumentType.LONGLONG]


class RiscV32SysVMktime(Mktime, RiscV32SysVModel):
    time_t = ArgumentType.LONGLONG
    return_type = ArgumentType.LONGLONG


class RiscV32SysVClock(Clock, RiscV32SysVModel):
    pass


__all__ = [
    "RiscV32SysVTime",
    "RiscV32SysVLocaltime",
    "RiscV32SysVGmtime",
    "RiscV32SysVCtime",
    "RiscV32SysVAsctime",
    "RiscV32SysVStrftime",
    "RiscV32SysVDifftime",
    "RiscV32SysVMktime",
    "RiscV32SysVClock",
]
