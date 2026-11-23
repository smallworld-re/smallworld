from ....c99.signal import Raise, Signal
from ..systemv import AArch64V85ASysVModel


class AArch64V85ASysVRaise(Raise, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVSignal(Signal, AArch64V85ASysVModel):
    pass


__all__ = [
    "AArch64V85ASysVRaise",
    "AArch64V85ASysVSignal",
]
