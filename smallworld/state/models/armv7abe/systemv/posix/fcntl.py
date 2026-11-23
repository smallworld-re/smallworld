from ....posix.fcntl import Creat, Open
from ..systemv import ArmV7ABESysVModel


class ArmV7ABESysVOpen(Open, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVCreat(Creat, ArmV7ABESysVModel):
    pass


__all__ = ["ArmV7ABESysVOpen", "ArmV7ABESysVCreat"]
