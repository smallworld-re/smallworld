from ....posix.fcntl import Creat, Open
from ..systemv import RiscV64SysVModel


class RiscV64SysVOpen(Open, RiscV64SysVModel):
    pass


class RiscV64SysVCreat(Creat, RiscV64SysVModel):
    pass


__all__ = ["RiscV64SysVOpen", "RiscV64SysVCreat"]
