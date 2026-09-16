from ....posix.fcntl import Creat, Open
from ..systemv import LoongArch64SysVModel


class LoongArch64SysVOpen(Open, LoongArch64SysVModel):
    pass


class LoongArch64SysVCreat(Creat, LoongArch64SysVModel):
    pass


__all__ = ["LoongArch64SysVOpen", "LoongArch64SysVCreat"]
