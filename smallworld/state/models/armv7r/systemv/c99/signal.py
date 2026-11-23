from ....c99.signal import Raise, Signal
from ..systemv import ArmV7RSysVModel


class ArmV7RSysVRaise(Raise, ArmV7RSysVModel):
    pass


class ArmV7RSysVSignal(Signal, ArmV7RSysVModel):
    pass


__all__ = [
    "ArmV7RSysVRaise",
    "ArmV7RSysVSignal",
]
