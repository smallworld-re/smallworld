from ....posix.fcntl import Creat, Open
from ..systemv import M68KSysVModel


class M68KSysVOpen(Open, M68KSysVModel):
    pass


class M68KSysVCreat(Creat, M68KSysVModel):
    pass


__all__ = ["M68KSysVOpen", "M68KSysVCreat"]
