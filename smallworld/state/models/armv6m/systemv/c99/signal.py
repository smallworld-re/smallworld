from ....c99.signal import Raise, Signal
from ..systemv import ArmV6MSysVModel


class ArmV6MSysVRaise(Raise, ArmV6MSysVModel):
    pass


class ArmV6MSysVSignal(Signal, ArmV6MSysVModel):
    pass


__all__ = [
    "ArmV6MSysVRaise",
    "ArmV6MSysVSignal",
]
