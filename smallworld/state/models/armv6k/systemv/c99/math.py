from ....c99.math import Fabs
from ..systemv import ArmV6KSysVModel


class ArmV6KSysVFabs(Fabs, ArmV6KSysVModel):
    pass


__all__ = ["ArmV6KSysVFabs"]
