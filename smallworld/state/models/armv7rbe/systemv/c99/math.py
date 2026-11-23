from ....c99.math import Fabs
from ..systemv import ArmV7RBESysVModel


class ArmV7RBESysVFabs(Fabs, ArmV7RBESysVModel):
    pass


__all__ = ["ArmV7RBESysVFabs"]
