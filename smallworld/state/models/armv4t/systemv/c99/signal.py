from ....c99.signal import Raise, Signal
from ..systemv import ArmV4TSysVModel


class ArmV4TSysVRaise(Raise, ArmV4TSysVModel):
    pass


class ArmV4TSysVSignal(Signal, ArmV4TSysVModel):
    pass


__all__ = [
    "ArmV4TSysVRaise",
    "ArmV4TSysVSignal",
]
