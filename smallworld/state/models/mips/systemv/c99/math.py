from ....c99.math import Fabs
from ..systemv import MIPSSysVModel


class MIPSSysVFabs(Fabs, MIPSSysVModel):
    pass


__all__ = ["MIPSSysVFabs"]
