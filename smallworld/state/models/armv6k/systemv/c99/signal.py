from ....c99.signal import Raise, Signal
from ..systemv import ArmV6KSysVModel


class ArmV6KSysVRaise(Raise, ArmV6KSysVModel):
    pass


class ArmV6KSysVSignal(Signal, ArmV6KSysVModel):
    pass


__all__ = [
    "ArmV6KSysVRaise",
    "ArmV6KSysVSignal",
]
