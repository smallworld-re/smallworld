from ....posix.fcntl import Creat, Open
from ..systemv import MicroMIPSELSysVModel


class MicroMIPSELSysVOpen(Open, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVCreat(Creat, MicroMIPSELSysVModel):
    pass


__all__ = ["MicroMIPSELSysVOpen", "MicroMIPSELSysVCreat"]
