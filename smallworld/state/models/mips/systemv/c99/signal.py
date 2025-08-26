from ....c99.signal import Raise, Signal
from ..systemv import MIPSSysVModel


class MIPSSysVRaise(Raise, MIPSSysVModel):
    pass


class MIPSSysVSignal(Signal, MIPSSysVModel):
    pass


__all__ = [
    "MIPSSysVRaise",
    "MIPSSysVSignal",
]
