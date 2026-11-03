from ....c99.math import Fabs
from ..systemv import AArch64V85ABESysVModel


class AArch64V85ABESysVFabs(Fabs, AArch64V85ABESysVModel):
    pass


__all__ = ["AArch64V85ABESysVFabs"]
