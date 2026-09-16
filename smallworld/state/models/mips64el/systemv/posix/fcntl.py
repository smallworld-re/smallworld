from ....posix.fcntl import Creat, Open
from ..systemv import MIPS64ELSysVModel


class MIPS64ELSysVOpen(Open, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVCreat(Creat, MIPS64ELSysVModel):
    pass


__all__ = ["MIPS64ELSysVOpen", "MIPS64ELSysVCreat"]
