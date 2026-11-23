from ....c99.signal import Raise, Signal
from ..systemv import ArmV6KBESysVModel


class ArmV6KBESysVRaise(Raise, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVSignal(Signal, ArmV6KBESysVModel):
    pass


__all__ = [
    "ArmV6KBESysVRaise",
    "ArmV6KBESysVSignal",
]
