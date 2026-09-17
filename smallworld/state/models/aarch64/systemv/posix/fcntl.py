from ....posix.fcntl import Creat, Open
from ..systemv import AArch64SysVModel


class AArch64SysVOpen(Open, AArch64SysVModel):
    pass


class AArch64SysVCreat(Creat, AArch64SysVModel):
    pass


__all__ = ["AArch64SysVOpen", "AArch64SysVCreat"]
