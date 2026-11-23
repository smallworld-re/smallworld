from ....posix.fcntl import Creat, Open
from ..systemv import ArmV8RSysVModel


class ArmV8RSysVOpen(Open, ArmV8RSysVModel):
    pass


class ArmV8RSysVCreat(Creat, ArmV8RSysVModel):
    pass


__all__ = ["ArmV8RSysVOpen", "ArmV8RSysVCreat"]
