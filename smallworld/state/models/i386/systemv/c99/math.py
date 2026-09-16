from ....c99.math import Fabs
from ..systemv import I386SysVModel


class I386SysVFabs(Fabs, I386SysVModel):
    pass


__all__ = ["I386SysVFabs"]
