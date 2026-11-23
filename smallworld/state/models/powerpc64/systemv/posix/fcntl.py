from ....posix.fcntl import Creat, Open
from ..systemv import PowerPC64SysVModel


class PowerPC64SysVOpen(Open, PowerPC64SysVModel):
    pass


class PowerPC64SysVCreat(Creat, PowerPC64SysVModel):
    pass


__all__ = ["PowerPC64SysVOpen", "PowerPC64SysVCreat"]
