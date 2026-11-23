from ....posix.fcntl import Creat, Open
from ..systemv import ArmV6KBESysVModel


class ArmV6KBESysVOpen(Open, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVCreat(Creat, ArmV6KBESysVModel):
    pass


__all__ = ["ArmV6KBESysVOpen", "ArmV6KBESysVCreat"]
