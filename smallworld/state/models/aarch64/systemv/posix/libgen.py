from ....posix.libgen import Basename, Dirname
from ..systemv import AArch64SysVModel


class AArch64SysVBasename(Basename, AArch64SysVModel):
    pass


class AArch64SysVDirname(Dirname, AArch64SysVModel):
    pass


__all__ = [
    "AArch64SysVBasename",
    "AArch64SysVDirname",
]
