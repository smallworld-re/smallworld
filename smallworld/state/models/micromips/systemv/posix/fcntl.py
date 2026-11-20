from ....posix.fcntl import Creat, Open
from ..systemv import MicroMIPSSysVModel


class MicroMIPSSysVOpen(Open, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVCreat(Creat, MicroMIPSSysVModel):
    pass


__all__ = ["MicroMIPSSysVOpen", "MicroMIPSSysVCreat"]
