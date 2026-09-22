from ....posix.fcntl import Creat, Open
from ..systemv import MIPS64SysVModel


class MIPS64SysVOpen(Open, MIPS64SysVModel):
    pass


class MIPS64SysVCreat(Creat, MIPS64SysVModel):
    pass


__all__ = ["MIPS64SysVOpen", "MIPS64SysVCreat"]
