from ....posix.fcntl import Creat, Open
from ..systemv import ArmV8ASysVModel


class ArmV8ASysVOpen(Open, ArmV8ASysVModel):
    pass


class ArmV8ASysVCreat(Creat, ArmV8ASysVModel):
    pass


__all__ = ["ArmV8ASysVOpen", "ArmV8ASysVCreat"]
