from ....c99.math import Fabs
from ..systemv import ArmV6KBESysVModel


class ArmV6KBESysVFabs(Fabs, ArmV6KBESysVModel):
    pass


__all__ = ["ArmV6KBESysVFabs"]
