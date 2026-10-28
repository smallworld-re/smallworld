from ....posix.fcntl import Creat, Open
from ..systemv import ArmV8ABESysVModel


class ArmV8ABESysVOpen(Open, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVCreat(Creat, ArmV8ABESysVModel):
    pass


__all__ = ["ArmV8ABESysVOpen", "ArmV8ABESysVCreat"]
