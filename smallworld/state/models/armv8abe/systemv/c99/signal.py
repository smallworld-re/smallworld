from ....c99.signal import Raise, Signal
from ..systemv import ArmV8ABESysVModel


class ArmV8ABESysVRaise(Raise, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVSignal(Signal, ArmV8ABESysVModel):
    pass


__all__ = [
    "ArmV8ABESysVRaise",
    "ArmV8ABESysVSignal",
]
