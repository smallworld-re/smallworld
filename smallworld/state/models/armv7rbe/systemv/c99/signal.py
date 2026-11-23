from ....c99.signal import Raise, Signal
from ..systemv import ArmV7RBESysVModel


class ArmV7RBESysVRaise(Raise, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVSignal(Signal, ArmV7RBESysVModel):
    pass


__all__ = [
    "ArmV7RBESysVRaise",
    "ArmV7RBESysVSignal",
]
