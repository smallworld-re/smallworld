from ....posix.fcntl import Creat, Open
from ..systemv import ArmV8MSysVModel


class ArmV8MSysVOpen(Open, ArmV8MSysVModel):
    pass


class ArmV8MSysVCreat(Creat, ArmV8MSysVModel):
    pass


__all__ = ["ArmV8MSysVOpen", "ArmV8MSysVCreat"]
