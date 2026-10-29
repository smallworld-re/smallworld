from ....posix.libgen import Basename, Dirname
from ..systemv import AArch64V85ASysVModel


class AArch64V85ASysVBasename(Basename, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVDirname(Dirname, AArch64V85ASysVModel):
    pass


__all__ = [
    "AArch64V85ASysVBasename",
    "AArch64V85ASysVDirname",
]
