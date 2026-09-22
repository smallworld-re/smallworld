from ....c99.math import Fabs
from ..systemv import AMD64SysVModel


class AMD64SysVFabs(Fabs, AMD64SysVModel):
    pass


__all__ = ["AMD64SysVFabs"]
