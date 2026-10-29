from ....c99.math import Fabs
from ..systemv import AArch64V85ASysVModel


class AArch64V85ASysVFabs(Fabs, AArch64V85ASysVModel):
    pass


__all__ = ["AArch64V85ASysVFabs"]
