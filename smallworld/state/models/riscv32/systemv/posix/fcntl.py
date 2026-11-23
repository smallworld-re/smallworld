from ....posix.fcntl import Creat, Open
from ..systemv import RiscV32SysVModel


class RiscV32SysVOpen(Open, RiscV32SysVModel):
    pass


class RiscV32SysVCreat(Creat, RiscV32SysVModel):
    pass


__all__ = ["RiscV32SysVOpen", "RiscV32SysVCreat"]
