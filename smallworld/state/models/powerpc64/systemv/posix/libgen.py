from ....posix.libgen import Basename, Dirname
from ..systemv import PowerPC64SysVModel


class PowerPC64SysVBasename(Basename, PowerPC64SysVModel):
    pass


class PowerPC64SysVDirname(Dirname, PowerPC64SysVModel):
    pass


__all__ = [
    "PowerPC64SysVBasename",
    "PowerPC64SysVDirname",
]
