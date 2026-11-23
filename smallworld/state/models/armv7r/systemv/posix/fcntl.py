from ....posix.fcntl import Creat, Open
from ..systemv import ArmV7RSysVModel


class ArmV7RSysVOpen(Open, ArmV7RSysVModel):
    pass


class ArmV7RSysVCreat(Creat, ArmV7RSysVModel):
    pass


__all__ = ["ArmV7RSysVOpen", "ArmV7RSysVCreat"]
