from ....posix.fcntl import Creat, Open
from ..systemv import ArmV4TSysVModel


class ArmV4TSysVOpen(Open, ArmV4TSysVModel):
    pass


class ArmV4TSysVCreat(Creat, ArmV4TSysVModel):
    pass


__all__ = ["ArmV4TSysVOpen", "ArmV4TSysVCreat"]
