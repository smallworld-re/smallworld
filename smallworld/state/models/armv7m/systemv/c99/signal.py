from ....c99.signal import Raise, Signal
from ..systemv import ArmV7MSysVModel


class ArmV7MSysVRaise(Raise, ArmV7MSysVModel):
    pass


class ArmV7MSysVSignal(Signal, ArmV7MSysVModel):
    pass


__all__ = [
    "ArmV7MSysVRaise",
    "ArmV7MSysVSignal",
]
