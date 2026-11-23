from ....c99.signal import Raise, Signal
from ..systemv import ArmV7ABESysVModel


class ArmV7ABESysVRaise(Raise, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVSignal(Signal, ArmV7ABESysVModel):
    pass


__all__ = [
    "ArmV7ABESysVRaise",
    "ArmV7ABESysVSignal",
]
