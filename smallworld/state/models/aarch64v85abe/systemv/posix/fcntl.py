from ....posix.fcntl import Creat, Open
from ..systemv import AArch64V85ABESysVModel


class AArch64V85ABESysVOpen(Open, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVCreat(Creat, AArch64V85ABESysVModel):
    pass


__all__ = ["AArch64V85ABESysVOpen", "AArch64V85ABESysVCreat"]
