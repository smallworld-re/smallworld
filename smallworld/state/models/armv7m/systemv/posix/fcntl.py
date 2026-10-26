from ....posix.fcntl import Creat, Open
from ..systemv import ArmV7MSysVModel


class ArmV7MSysVOpen(Open, ArmV7MSysVModel):
    pass


class ArmV7MSysVCreat(Creat, ArmV7MSysVModel):
    pass


__all__ = ["ArmV7MSysVOpen", "ArmV7MSysVCreat"]
