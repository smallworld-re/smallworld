from ....posix.fcntl import Creat, Open
from ..systemv import MIPSSysVModel


class MIPSSysVOpen(Open, MIPSSysVModel):
    pass


class MIPSSysVCreat(Creat, MIPSSysVModel):
    pass


__all__ = ["MIPSSysVOpen", "MIPSSysVCreat"]
