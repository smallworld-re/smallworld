from ....posix.libgen import Basename, Dirname
from ..systemv import RiscV32SysVModel


class RiscV32SysVBasename(Basename, RiscV32SysVModel):
    pass


class RiscV32SysVDirname(Dirname, RiscV32SysVModel):
    pass


__all__ = [
    "RiscV32SysVBasename",
    "RiscV32SysVDirname",
]
