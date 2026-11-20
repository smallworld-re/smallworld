from ....c99.signal import Raise, Signal
from ..systemv import MicroMIPSSysVModel


class MicroMIPSSysVRaise(Raise, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSignal(Signal, MicroMIPSSysVModel):
    pass


__all__ = [
    "MicroMIPSSysVRaise",
    "MicroMIPSSysVSignal",
]
