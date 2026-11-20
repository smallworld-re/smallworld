from ....c99.math import Fabs
from ..systemv import MicroMIPSSysVModel


class MicroMIPSSysVFabs(Fabs, MicroMIPSSysVModel):
    pass


__all__ = ["MicroMIPSSysVFabs"]
