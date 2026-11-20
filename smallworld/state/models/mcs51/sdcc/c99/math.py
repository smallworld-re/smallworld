from ....c99.math import Fabs
from ..sdcc import MCS51SDCCModel


class MCS51SDCCFabs(Fabs, MCS51SDCCModel):
    pass


__all__ = [
    "MCS51SDCCFabs",
]
