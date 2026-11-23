from ....c99.math import Fabs
from ..systemv import ArmV5TBESysVModel


class ArmV5TBESysVFabs(Fabs, ArmV5TBESysVModel):
    pass


__all__ = ["ArmV5TBESysVFabs"]
