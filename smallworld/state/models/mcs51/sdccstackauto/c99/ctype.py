from ....c99.ctype import (
    Tolower,
    Toupper,
)
from ..sdccstackauto import MCS51SDCCStackAutoModel


class MCS51SDCCStackAutoTolower(Tolower, MCS51SDCCStackAutoModel):
    pass


class MCS51SDCCStackAutoToupper(Toupper, MCS51SDCCStackAutoModel):
    pass


__all__ = [
    "MCS51SDCCStackAutoTolower",
    "MCS51SDCCStackAutoToupper",
]
