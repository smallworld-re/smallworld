from ....c99.signal import Raise, Signal
from ..systemv import ArmV5TSysVModel


class ArmV5TSysVRaise(Raise, ArmV5TSysVModel):
    pass


class ArmV5TSysVSignal(Signal, ArmV5TSysVModel):
    pass


__all__ = [
    "ArmV5TSysVRaise",
    "ArmV5TSysVSignal",
]
