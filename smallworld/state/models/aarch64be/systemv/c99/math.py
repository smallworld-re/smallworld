from ....c99.math import Fabs
from ..systemv import AArch64BESysVModel


class AArch64BESysVFabs(Fabs, AArch64BESysVModel):
    pass


__all__ = ["AArch64BESysVFabs"]
