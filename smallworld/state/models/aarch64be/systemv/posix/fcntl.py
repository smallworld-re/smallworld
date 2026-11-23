from ....posix.fcntl import Creat, Open
from ..systemv import AArch64BESysVModel


class AArch64BESysVOpen(Open, AArch64BESysVModel):
    pass


class AArch64BESysVCreat(Creat, AArch64BESysVModel):
    pass


__all__ = ["AArch64BESysVOpen", "AArch64BESysVCreat"]
