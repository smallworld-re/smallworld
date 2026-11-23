from ....c99.ctype import (
    Tolower,
    Toupper,
)
from ..sdcc import MCS51SDCCModel


class MCS51SDCCTolower(Tolower, MCS51SDCCModel):
    pass


class MCS51SDCCToupper(Toupper, MCS51SDCCModel):
    pass


__all__ = [
    "MCS51SDCCTolower",
    "MCS51SDCCToupper",
]
