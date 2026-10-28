from ....posix.fcntl import Creat, Open
from ..systemv import ArmV7ASysVModel


class ArmV7ASysVOpen(Open, ArmV7ASysVModel):
    pass


class ArmV7ASysVCreat(Creat, ArmV7ASysVModel):
    pass


__all__ = ["ArmV7ASysVOpen", "ArmV7ASysVCreat"]
