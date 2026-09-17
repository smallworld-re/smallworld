from ....posix.fcntl import Creat, Open
from ..systemv import PowerPCSysVModel


class PowerPCSysVOpen(Open, PowerPCSysVModel):
    pass


class PowerPCSysVCreat(Creat, PowerPCSysVModel):
    pass


__all__ = ["PowerPCSysVOpen", "PowerPCSysVCreat"]
