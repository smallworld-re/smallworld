from ....posix.fcntl import Creat, Open
from ..systemv import AMD64SysVModel


class AMD64SysVOpen(Open, AMD64SysVModel):
    pass


class AMD64SysVCreat(Creat, AMD64SysVModel):
    pass


__all__ = ["AMD64SysVOpen", "AMD64SysVCreat"]
