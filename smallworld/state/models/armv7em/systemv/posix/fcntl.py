from ....posix.fcntl import Creat, Open
from ..systemv import ArmV7EMSysVModel


class ArmV7EMSysVOpen(Open, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVCreat(Creat, ArmV7EMSysVModel):
    pass


__all__ = ["ArmV7EMSysVOpen", "ArmV7EMSysVCreat"]
