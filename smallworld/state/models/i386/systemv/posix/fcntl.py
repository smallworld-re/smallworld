from ....posix.fcntl import Creat, Open
from ..systemv import I386SysVModel


class I386SysVOpen(Open, I386SysVModel):
    pass


class I386SysVCreat(Creat, I386SysVModel):
    pass


__all__ = ["I386SysVOpen", "I386SysVCreat"]
