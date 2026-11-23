from ....posix.fcntl import Creat, Open
from ..systemv import ArmV8RBESysVModel


class ArmV8RBESysVOpen(Open, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVCreat(Creat, ArmV8RBESysVModel):
    pass


__all__ = ["ArmV8RBESysVOpen", "ArmV8RBESysVCreat"]
