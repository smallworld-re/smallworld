from ....posix.fcntl import Creat, Open
from ..systemv import ArmV5TSysVModel


class ArmV5TSysVOpen(Open, ArmV5TSysVModel):
    pass


class ArmV5TSysVCreat(Creat, ArmV5TSysVModel):
    pass


__all__ = ["ArmV5TSysVOpen", "ArmV5TSysVCreat"]
