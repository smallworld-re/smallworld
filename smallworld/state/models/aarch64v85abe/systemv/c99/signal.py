from ....c99.signal import Raise, Signal
from ..systemv import AArch64V85ABESysVModel


class AArch64V85ABESysVRaise(Raise, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVSignal(Signal, AArch64V85ABESysVModel):
    pass


__all__ = [
    "AArch64V85ABESysVRaise",
    "AArch64V85ABESysVSignal",
]
