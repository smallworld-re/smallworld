from ....c99.signal import Raise, Signal
from ..systemv import ArmV8RSysVModel


class ArmV8RSysVRaise(Raise, ArmV8RSysVModel):
    pass


class ArmV8RSysVSignal(Signal, ArmV8RSysVModel):
    pass


__all__ = [
    "ArmV8RSysVRaise",
    "ArmV8RSysVSignal",
]
