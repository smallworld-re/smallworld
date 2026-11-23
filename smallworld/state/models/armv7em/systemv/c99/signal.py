from ....c99.signal import Raise, Signal
from ..systemv import ArmV7EMSysVModel


class ArmV7EMSysVRaise(Raise, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVSignal(Signal, ArmV7EMSysVModel):
    pass


__all__ = [
    "ArmV7EMSysVRaise",
    "ArmV7EMSysVSignal",
]
