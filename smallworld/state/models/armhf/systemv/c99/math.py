from ....c99.math import Fabs
from ..systemv import ArmHFSysVModel


class ArmHFSysVFabs(Fabs, ArmHFSysVModel):
    pass


__all__ = ["ArmHFSysVFabs"]
