from ....posix.fcntl import Creat, Open
from ..systemv import ArmV7RBESysVModel


class ArmV7RBESysVOpen(Open, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVCreat(Creat, ArmV7RBESysVModel):
    pass


__all__ = ["ArmV7RBESysVOpen", "ArmV7RBESysVCreat"]
