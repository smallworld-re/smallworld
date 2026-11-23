from ....posix.fcntl import Creat, Open
from ..systemv import AArch64V85ASysVModel


class AArch64V85ASysVOpen(Open, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVCreat(Creat, AArch64V85ASysVModel):
    pass


__all__ = ["AArch64V85ASysVOpen", "AArch64V85ASysVCreat"]
