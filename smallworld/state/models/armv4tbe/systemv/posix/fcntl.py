from ....posix.fcntl import Creat, Open
from ..systemv import ArmV4TBESysVModel


class ArmV4TBESysVOpen(Open, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVCreat(Creat, ArmV4TBESysVModel):
    pass


__all__ = ["ArmV4TBESysVOpen", "ArmV4TBESysVCreat"]
