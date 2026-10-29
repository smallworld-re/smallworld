from ....c99.math import Fabs
from ..sdccstackauto import MCS51SDCCStackAutoModel


class MCS51SDCCStackAutoFabs(Fabs, MCS51SDCCStackAutoModel):
    pass


__all__ = [
    "MCS51SDCCStackAutoFabs",
]
