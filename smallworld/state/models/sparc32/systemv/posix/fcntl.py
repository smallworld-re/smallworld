from ....posix.fcntl import Creat, Open
from ..systemv import SPARC32SysVModel


class SPARC32SysVOpen(Open, SPARC32SysVModel):
    pass


class SPARC32SysVCreat(Creat, SPARC32SysVModel):
    pass


__all__ = ["SPARC32SysVOpen", "SPARC32SysVCreat"]
