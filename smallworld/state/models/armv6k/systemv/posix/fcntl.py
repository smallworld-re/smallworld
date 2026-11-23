from ....posix.fcntl import Creat, Open
from ..systemv import ArmV6KSysVModel


class ArmV6KSysVOpen(Open, ArmV6KSysVModel):
    pass


class ArmV6KSysVCreat(Creat, ArmV6KSysVModel):
    pass


__all__ = ["ArmV6KSysVOpen", "ArmV6KSysVCreat"]
