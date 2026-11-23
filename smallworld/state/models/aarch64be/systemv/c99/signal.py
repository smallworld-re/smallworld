from ....c99.signal import Raise, Signal
from ..systemv import AArch64BESysVModel


class AArch64BESysVRaise(Raise, AArch64BESysVModel):
    pass


class AArch64BESysVSignal(Signal, AArch64BESysVModel):
    pass


__all__ = [
    "AArch64BESysVRaise",
    "AArch64BESysVSignal",
]
