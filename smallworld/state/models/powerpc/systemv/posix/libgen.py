from ....posix.libgen import Basename, Dirname
from ..systemv import PowerPCSysVModel


class PowerPCSysVBasename(Basename, PowerPCSysVModel):
    pass


class PowerPCSysVDirname(Dirname, PowerPCSysVModel):
    pass


__all__ = [
    "PowerPCSysVBasename",
    "PowerPCSysVDirname",
]
