from ....posix.fcntl import Creat, Open
from ..systemv import ArmHFSysVModel


class ArmHFSysVOpen(Open, ArmHFSysVModel):
    pass


class ArmHFSysVCreat(Creat, ArmHFSysVModel):
    pass


__all__ = ["ArmHFSysVOpen", "ArmHFSysVCreat"]
