from ....posix.fcntl import Creat, Open
from ..systemv import ArmELSysVModel


class ArmELSysVOpen(Open, ArmELSysVModel):
    pass


class ArmELSysVCreat(Creat, ArmELSysVModel):
    pass


__all__ = ["ArmELSysVOpen", "ArmELSysVCreat"]
