from ....posix.fcntl import Creat, Open
from ..systemv import MIPSELSysVModel


class MIPSELSysVOpen(Open, MIPSELSysVModel):
    pass


class MIPSELSysVCreat(Creat, MIPSELSysVModel):
    pass


__all__ = ["MIPSELSysVOpen", "MIPSELSysVCreat"]
