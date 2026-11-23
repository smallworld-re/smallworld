from ....posix.fcntl import Creat, Open
from ..systemv import ArmV5TBESysVModel


class ArmV5TBESysVOpen(Open, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVCreat(Creat, ArmV5TBESysVModel):
    pass


__all__ = ["ArmV5TBESysVOpen", "ArmV5TBESysVCreat"]
