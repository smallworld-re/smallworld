from ....c99.signal import Raise, Signal
from ..systemv import ArmV8ASysVModel


class ArmV8ASysVRaise(Raise, ArmV8ASysVModel):
    pass


class ArmV8ASysVSignal(Signal, ArmV8ASysVModel):
    pass


__all__ = [
    "ArmV8ASysVRaise",
    "ArmV8ASysVSignal",
]
