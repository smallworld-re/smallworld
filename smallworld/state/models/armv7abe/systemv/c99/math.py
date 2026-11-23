from ....c99.math import Fabs
from ..systemv import ArmV7ABESysVModel


class ArmV7ABESysVFabs(Fabs, ArmV7ABESysVModel):
    pass


__all__ = ["ArmV7ABESysVFabs"]
