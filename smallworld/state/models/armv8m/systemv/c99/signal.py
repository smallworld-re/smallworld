from ....c99.signal import Raise, Signal
from ..systemv import ArmV8MSysVModel


class ArmV8MSysVRaise(Raise, ArmV8MSysVModel):
    pass


class ArmV8MSysVSignal(Signal, ArmV8MSysVModel):
    pass


__all__ = [
    "ArmV8MSysVRaise",
    "ArmV8MSysVSignal",
]
