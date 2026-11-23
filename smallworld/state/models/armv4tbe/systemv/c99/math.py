from ....c99.math import Fabs
from ..systemv import ArmV4TBESysVModel


class ArmV4TBESysVFabs(Fabs, ArmV4TBESysVModel):
    pass


__all__ = ["ArmV4TBESysVFabs"]
