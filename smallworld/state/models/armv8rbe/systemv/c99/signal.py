from ....c99.signal import Raise, Signal
from ..systemv import ArmV8RBESysVModel


class ArmV8RBESysVRaise(Raise, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVSignal(Signal, ArmV8RBESysVModel):
    pass


__all__ = [
    "ArmV8RBESysVRaise",
    "ArmV8RBESysVSignal",
]
