from ....posix.libgen import Basename, Dirname
from ..systemv import LoongArch64SysVModel


class LoongArch64SysVBasename(Basename, LoongArch64SysVModel):
    pass


class LoongArch64SysVDirname(Dirname, LoongArch64SysVModel):
    pass


__all__ = [
    "LoongArch64SysVBasename",
    "LoongArch64SysVDirname",
]
