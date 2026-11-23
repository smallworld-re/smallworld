from ....posix.fcntl import Creat, Open
from ..systemv import ArmV6MSysVModel


class ArmV6MSysVOpen(Open, ArmV6MSysVModel):
    pass


class ArmV6MSysVCreat(Creat, ArmV6MSysVModel):
    pass


__all__ = ["ArmV6MSysVOpen", "ArmV6MSysVCreat"]
