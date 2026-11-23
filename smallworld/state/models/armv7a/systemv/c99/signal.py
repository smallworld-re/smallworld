from ....c99.signal import Raise, Signal
from ..systemv import ArmV7ASysVModel


class ArmV7ASysVRaise(Raise, ArmV7ASysVModel):
    pass


class ArmV7ASysVSignal(Signal, ArmV7ASysVModel):
    pass


__all__ = [
    "ArmV7ASysVRaise",
    "ArmV7ASysVSignal",
]
